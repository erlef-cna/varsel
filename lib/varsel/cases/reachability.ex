# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability do
  @moduledoc """
  Deduces the affected version ranges of a vulnerability from git containment
  facts, treating the repository — not version numbers — as the source of truth.

  ## Model

  A release tag is **affected** iff its commit contains *some* introducing commit
  and *no* fixing commit. Expressed as set algebra over the tags each commit is
  contained by:

      affected = (⋃ intro → tags_containing(intro)) \\ (⋃ fix → tags_containing(fix))

  `derive/4` gathers those sets from the `Varsel.Cases.Derivation.GitBackend`
  (one `tags_containing/2` per commit plus `all_tags/1` for the full version
  universe) and hands the pure `deduce/3` the tag universe and the affected set.

  ## Flattening

  `deduce/3` orders every release version onto one linear timeline by its
  semantic version (semver order; the full OTP tree, from git, totally-ordered),
  drops the leading unaffected prefix (versions predating the vulnerability),
  then cuts the timeline into maximal runs of affected versions. Each run is one
  range `[first-affected, first-safe-after)`, spanning as many minor/major lines
  as it covers — so a vulnerability affecting all of `1.3.*` and `1.4.*` yields a
  single range, not one per line. A run reaching the newest version unfixed is
  open-ended; a fix followed by a re-introduction is simply the next range.
  Non-release tags (`nightly`, `v1.19-latest`, OTP topic tags) drop out.

  The output (`t:result/0`) carries the ranges, `pending_fixes` (a fix commit in
  no tag), an `open?` flag (some range is unbounded), `prerelease_conflict`
  call-outs (an excluded pre-release whose status disagrees with its neighbours),
  and issues. Serialization to CVE JSON is a separate concern.
  """

  alias Varsel.Cases.Derivation.GitBackend
  alias Varsel.Cases.Reachability.VersionComparator

  @type kind :: VersionComparator.kind()

  @type range :: %{
          from: String.t(),
          until: String.t() | :unbounded
        }

  @type call_out :: %{
          reason: :prerelease_conflict,
          version: String.t(),
          dag_label: :affected | :safe
        }

  @type result :: %{
          ranges: [range()],
          call_outs: [call_out()],
          open?: boolean(),
          pending_fixes: [String.t()],
          issues: [String.t()]
        }

  @doc """
  Resolves a package's affected ranges from git. Gathers containment from the
  configured `GitBackend` and runs `deduce/3`.

    * `repo_url` — the repository the commits live in.
    * `intros` / `fixes` — introducing / fixing commit SHAs.
    * `opts` — see `deduce/3` (`:comparator` required, `:include_prereleases`),
      plus `:explicit_versions` (see below).

  ## Explicit versions

  `:explicit_versions` carries `{event, version}` boundary facts naming releases
  git containment cannot see — a version published to the registry but never
  tagged (`boruta_auth` shipped 2.3.0/2.3.1 to Hex with no matching tag), or a
  boundary on a package whose releases are not tagged at all. Each is injected
  into the tag universe as if the tag existed, then labelled: an `:introduced`
  version marks itself *and every later release* affected up to the next explicit
  fix — the same forward propagation a real introducing commit gets from
  containment — while a `:fixed` version marks only itself safe. From there they
  flow through the normal run-cutting, so they bound ranges exactly like tags —
  which is what makes them work for a missing fix tag or a later range's intro,
  not just the earliest bound.

  An explicit version that *does* exist as a tag wins over its containment label:
  the human asserted it, so it is not second-guessed.

  `{:error, reason}` if the tag universe cannot be obtained (clone/fetch failure).
  A commit that resolves to no tag is not fatal: an unresolvable intro yields an
  issue, an unresolvable/unreleased fix becomes a `pending_fix`.
  """
  @spec derive(String.t(), [String.t()], [String.t()], keyword()) ::
          {:ok, result()} | {:error, term()}
  def derive(repo_url, intros, fixes, opts) do
    with {:ok, all_tags} <- GitBackend.all_tags(repo_url) do
      {explicit, opts} = Keyword.pop(opts, :explicit_versions, [])

      intro_tags = union_containing(repo_url, intros)
      {fix_tags, pending} = fix_containment(repo_url, fixes)

      derived_affected = MapSet.difference(intro_tags, fix_tags)

      # A commit-derived intro is only "contained in no release" when no explicit
      # version supplies the boundary either.
      issues =
        if intros != [] and MapSet.size(intro_tags) == 0 and explicit_intros(explicit) == [],
          do: ["the introducing commit is contained in no release tag"],
          else: []

      universe = Enum.uniq(all_tags ++ Enum.map(explicit, &elem(&1, 1)))
      kind = Keyword.fetch!(opts, :comparator)

      affected =
        apply_explicit(derived_affected, explicit, universe, kind, derived_safe: fix_tags)

      result = deduce(universe, affected, opts)
      {:ok, %{result | pending_fixes: pending, issues: result.issues ++ issues}}
    end
  end

  defp explicit_intros(explicit), do: for({:introduced, version} <- explicit, do: version)

  # Explicit labels are asserted, so they override containment. An `:introduced`
  # version propagates forward — it and every later release up to the next
  # explicit fix — mirroring what git containment does for a real introducing
  # commit; a `:fixed` version marks only itself safe, since later releases keep
  # the fix. Applied newest-boundary-first so an intro/fix pair cuts cleanly.
  defp apply_explicit(affected, [], _universe, _kind, _opts), do: affected

  defp apply_explicit(affected, explicit, universe, kind, opts) do
    fixes = for {:fixed, version} <- explicit, do: version

    # A release git already knows carries the fix stays fixed — containment saw
    # the fix commit in it, a stronger fact than propagating an earlier intro
    # forward. Re-introduction is the exception: an explicit intro *newer* than
    # the fixed release is asserting the vulnerability came back, so it wins.
    derived_safe = Keyword.fetch!(opts, :derived_safe)

    intro_affected =
      for {:introduced, intro} <- explicit,
          version <- universe,
          at_or_after?(kind, version, intro),
          not shadowed_by_derived_fix?(kind, derived_safe, version, intro),
          not fixed_between?(kind, fixes, intro, version),
          do: version

    affected
    |> MapSet.union(MapSet.new(intro_affected))
    |> MapSet.difference(MapSet.new(fixes))
  end

  defp at_or_after?(kind, version, boundary) do
    VersionComparator.compare(kind, version, boundary) != :lt
  end

  # Whether git's own "this release carries the fix" beats propagating `intro`
  # onto `version`. It does unless the intro is the newer fact — an explicit
  # intro at or after a fixed release is asserting a re-introduction.
  defp shadowed_by_derived_fix?(kind, derived_safe, version, intro) do
    MapSet.member?(derived_safe, version) and not at_or_after?(kind, intro, version)
  end

  # Whether an explicit fix lands in `(intro, version]` — i.e. the affected span
  # opened at `intro` is already closed by the time we reach `version`.
  defp fixed_between?(kind, fixes, intro, version) do
    Enum.any?(fixes, fn fix ->
      VersionComparator.compare(kind, fix, intro) != :lt and
        at_or_after?(kind, version, fix)
    end)
  end

  @doc """
  The pure core: given the full `all_tags` universe and the set of `affected` tag
  names, orders the releases and cuts them into affected ranges.

  Options:

    * `:comparator` (required) — `:semver` | `:otp`.
    * `:include_prereleases` (default `true`) — whether pre-release tags may bound
      ranges. `false` for OTP (it does not report them); excluded pre-releases are
      still checked and surface as `:prerelease_conflict` call-outs when their
      status disagrees with the surrounding releases.
  """
  @spec deduce([String.t()], MapSet.t(String.t()), keyword()) :: result()
  def deduce(all_tags, affected, opts) do
    kind = Keyword.fetch!(opts, :comparator)
    include_prereleases = Keyword.get(opts, :include_prereleases, true)

    labeled =
      for name <- Enum.uniq(all_tags), VersionComparator.release?(kind, name) do
        %{
          version: name,
          affected?: MapSet.member?(affected, name),
          prerelease?: VersionComparator.prerelease?(kind, name)
        }
      end

    {considered, excluded_prereleases} =
      if include_prereleases,
        do: {labeled, []},
        else: Enum.split_with(labeled, &(not &1.prerelease?))

    {ranges, has_open?} = collapse(kind, considered)

    %{
      ranges: ranges,
      call_outs: prerelease_call_outs(kind, considered, excluded_prereleases),
      open?: has_open?,
      pending_fixes: [],
      issues: []
    }
  end

  ## ------------------------------------------------------------ containment

  defp union_containing(repo_url, shas) do
    Enum.reduce(shas, MapSet.new(), fn sha, acc ->
      MapSet.union(acc, tags_containing(repo_url, sha))
    end)
  end

  # Fix tags, plus the fixes that reach no tag (unreleased / rebased -> pending).
  defp fix_containment(repo_url, fixes) do
    {tags, pending} =
      Enum.reduce(fixes, {MapSet.new(), []}, fn sha, {tags, pending} ->
        containing = tags_containing(repo_url, sha)

        if MapSet.size(containing) == 0,
          do: {tags, [sha | pending]},
          else: {MapSet.union(tags, containing), pending}
      end)

    {tags, Enum.reverse(pending)}
  end

  defp tags_containing(repo_url, sha) do
    case GitBackend.tags_containing(repo_url, sha) do
      {:ok, tags} -> MapSet.new(tags)
      {:error, _reason} -> MapSet.new()
    end
  end

  ## ---------------------------------------------------------------- collapse

  # Flatten every version onto one linearly-ordered timeline, drop the leading
  # unaffected prefix, then cut the timeline into maximal runs of affected
  # versions. Each run is one range `[first-affected, first-safe-after)` — or
  # open-ended when it reaches the newest version unfixed.
  defp collapse(kind, labeled) do
    ranges =
      kind
      |> VersionComparator.sort(labeled, & &1.version)
      |> chunk_by_status()
      |> ranges_from_runs()

    {ranges, Enum.any?(ranges, &(&1.until == :unbounded))}
  end

  # Consecutive same-status runs across the whole timeline: {affected?, [entry]}.
  # The leading unaffected run (pre-intro) is dropped by ranges_from_runs.
  defp chunk_by_status(sorted) do
    sorted
    |> Enum.chunk_by(& &1.affected?)
    |> Enum.map(fn [%{affected?: affected?} | _] = run -> {affected?, run} end)
  end

  # An affected run becomes [first, next-run's-first). The upper bound is the
  # first version of the immediately following (unaffected) run; a trailing
  # affected run has no follower -> :unbounded.
  defp ranges_from_runs(runs) do
    runs
    |> Enum.with_index()
    |> Enum.flat_map(fn
      {{true, run}, index} -> [range_for(run, Enum.at(runs, index + 1))]
      {{false, _run}, _index} -> []
    end)
  end

  defp range_for(run, next_run) do
    %{from: List.first(run).version, until: upper_bound(next_run)}
  end

  defp upper_bound({false, [safe | _]}), do: safe.version
  defp upper_bound(nil), do: :unbounded

  ## ---------------------------------------------------------------- prereleases

  # When pre-releases are excluded (OTP), flag the surprising case: an excluded
  # pre-release that is *affected* while its own release is *safe* — i.e. the fix
  # reached the release but not the pre-release, so anyone on that pre-release is
  # still exposed but we are not reporting it. The reverse (a pre-release safe
  # below an affected release) is just the range's lower boundary, not an anomaly.
  defp prerelease_call_outs(_kind, _considered, []), do: []

  defp prerelease_call_outs(kind, considered, excluded) do
    considered_sorted = VersionComparator.sort(kind, considered, & &1.version)

    for pre <- excluded,
        pre.affected?,
        release = its_release(kind, considered_sorted, pre.version),
        not release.affected? do
      %{reason: :prerelease_conflict, version: pre.version, dag_label: :affected}
    end
  end

  # The release a pre-release belongs to: the first considered release at-or-above
  # it (a pre-release sorts just below its own `x.y.z` release). `nil` when the
  # pre-release is newer than every release — then it has no line to conflict
  # with and is simply excluded.
  defp its_release(kind, considered_sorted, version) do
    Enum.find(considered_sorted, &(VersionComparator.compare(kind, &1.version, version) != :lt))
  end
end
