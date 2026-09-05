# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.Emit do
  @moduledoc """
  Shapes the neutral affected ranges from `Varsel.Cases.Reachability` into the
  CVE `versions[]` blocks each distribution channel publishes.

  `Reachability` reports ranges as raw tag-name bounds (`{from: "v1.7.0", until:
  "v1.7.22"}` / `{from: "OTP-27.0", until: "OTP-27.3.4.3"}`). This module strips
  the tag prefix and formats each bound in the channel's *version type* — the
  vocabulary it publishes in, stored on the channel rather than guessed from its
  purl type:

    * **semver** — bare bounded ranges.
    * **otp** — OTP release bounds as published (`17.0`, `27.3.4`). A channel
      naming a single OTP application (`pkg:otp/<app>`) has each bound
      translated to that application's own version through
      `Varsel.Cases.Derivation.OtpVersionsTable`.
    * **git** — a commit-SHA range per fix commit, from the raw boundary facts:
      commit SHAs are opaque, so no release version appears here.
    * **date** / **other** — the bounds verbatim.

  Every channel then applies its tag decoration: `tag_prefix` prepended and one
  range emitted per `tag_suffixes` flavor (`<prefix><version>-<suffix>`). A
  `"-"` suffix emits the bare version, so a channel publishing both `1.2.3` and
  `1.2.3-special` lists `["-", "special"]`; an empty list emits the version
  alone.

  A totally ordered scheme publishes one `versions[]` object per range
  (`{version, lessThan, status, versionType}`), with an unbounded range
  rendering `lessThan: "*"`. A scheme whose versions only order partially
  cannot: a bounded range asserts an order between its bounds that OTP's
  maintenance patches do not have (see `Varsel.Cases.Reachability.OTPVersion`).
  Those publish one open entry carrying a `changes[]` transition per fix, which
  the schema resolves by applying every transition at or below the version
  asked about. Commit SHAs have no order at all and take the same shape.
  """

  alias Varsel.Cases.Derivation.OtpVersionsTable
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.PackageChannel.PurlType
  alias Varsel.Cases.Reachability
  alias Varsel.Cases.Reachability.VersionComparator

  @type range :: Reachability.range()

  # The suffix standing for the undecorated version. A form's comma separated
  # list cannot carry an empty entry, since Ash trims it away, so the bare
  # flavor is stored as this marker instead.
  @bare_tag "-"

  @doc """
  The `versions[]` block for a repo-derived channel: `%{"versions" => [...],
  "issues" => [...]}`. `pending` is added by the caller (it is package-level).

  `opts` carries the boundary facts the git version type needs
  (`:intro_shas` / `:fix_shas`), the derived `:boundaries`, and the package's
  effective `:default_status`.
  """
  @spec channel(PackageChannel.t(), [range()], keyword()) :: %{
          required(String.t()) => [map()]
        }
  def channel(channel, ranges, opts) do
    emit(version_type(channel), channel, ranges, opts)
  end

  defp emit(:git, _channel, _ranges, opts) do
    git(Keyword.get(opts, :intro_shas, []), Keyword.get(opts, :fix_shas, []))
  end

  defp emit(version_type, channel, ranges, opts) do
    versions(channel, version_type, ranges, opts)
  end

  @doc """
  The version type a channel publishes in: its own when set, else its purl
  type's default. Service channels are always dated.
  """
  @spec version_type(PackageChannel.t() | map()) :: atom()
  def version_type(%{kind: :service}), do: :date
  def version_type(%{version_type: version_type}) when not is_nil(version_type), do: version_type
  def version_type(channel), do: PurlType.default_version_type(channel.purl_type)

  @doc """
  cpeApplicability matches from the neutral ranges: each `[from, until)` is one
  non-overlapping `%{versionStartIncluding, versionEndExcluding}` (bare versions).

  CPE has only one status, so a match means "possibly affected" and an unmatched
  version reads as safe. Everything the record does not call unaffected is
  therefore matched, which is the worst reading of what it says:

    * `unaffected` default: the affected ranges.
    * `unknown` default: the same, with the lowest match dropping its lower
      bound so the unclaimed pre-introduction span falls inside it. This is how
      NVD writes OTP's lowest affected line (`{versionEndExcluding:
      "23.3.4.15"}`, no start).
    * `affected` default: the gaps between the fix-carrying spans, since those
      spans are the only versions the record calls safe.
  """
  @spec cpe_matches([range()], keyword()) :: [map()]
  def cpe_matches(ranges, opts \\ []) do
    case Keyword.get(opts, :default_status, :unaffected) do
      :affected -> opts |> Keyword.get(:fixed_ranges, []) |> gaps_between()
      :unknown -> affected_matches(ranges, true)
      _unaffected -> affected_matches(ranges, false)
    end
  end

  defp affected_matches(ranges, drop_lowest_bound?) do
    # Reachability emits ranges in ascending release order, so the first is the
    # lowest, and the only one an unclaimed span borders.
    for {range, index} <- Enum.with_index(ranges) do
      # cpe has no "*" sentinel: an open range simply has no upper bound.
      upper = if range.until == :unbounded, do: nil, else: bare(range.until)
      lower = if drop_lowest_bound? and index == 0, do: nil, else: bare(range.from)

      %{"versionStartIncluding" => lower, "versionEndExcluding" => upper}
    end
  end

  defp gaps_between(fixed_ranges) do
    {gaps, last_end} =
      Enum.reduce(fixed_ranges, {[], nil}, fn range, {matches, previous_end} ->
        match = %{
          "versionStartIncluding" => previous_end,
          "versionEndExcluding" => bare(range.from)
        }

        {[match | matches], upper_of(range)}
      end)

    Enum.reverse(trailing_gap(last_end, fixed_ranges) ++ gaps)
  end

  # Nothing listed as safe, so every version is possibly affected.
  defp trailing_gap(_last_end, []), do: [%{"versionStartIncluding" => nil, "versionEndExcluding" => nil}]

  # A fix carried to the newest release leaves nothing above it.
  defp trailing_gap(nil, _fixed_ranges), do: []

  defp trailing_gap(last_end, _fixed_ranges), do: [%{"versionStartIncluding" => last_end, "versionEndExcluding" => nil}]

  defp upper_of(%{until: :unbounded}), do: nil
  defp upper_of(%{until: until}), do: bare(until)

  ## ------------------------------------------------------------ decoration

  defp decorated_ranges(channel, ranges, version_type, status) do
    prefix = channel.tag_prefix || ""
    suffixes = if channel.tag_suffixes in [nil, []], do: [@bare_tag], else: channel.tag_suffixes

    for suffix <- suffixes, range <- ranges do
      version_object(
        decorate(prefix, bare(range.from), suffix),
        decorated_bound(prefix, range.until, suffix),
        version_type,
        status
      )
    end
  end

  defp decorate(prefix, version, @bare_tag), do: "#{prefix}#{version}"
  defp decorate(prefix, version, suffix), do: "#{prefix}#{version}-#{suffix}"

  defp decorated_bound(_prefix, :unbounded, _suffix), do: "*"
  defp decorated_bound(prefix, until, suffix), do: decorate(prefix, bare(until), suffix)

  ## ------------------------------------------------------------ versions

  defp versions(channel, version_type, ranges, opts) do
    statused = statused_ranges(ranges, opts)

    if VersionComparator.total_order?(version_type) do
      flat_versions(channel, version_type, statused)
    else
      status_change_versions(channel, version_type, statused, opts)
    end
  end

  defp status_change_versions(channel, version_type, statused, opts) do
    boundaries =
      opts
      |> Keyword.get(:boundaries)
      |> open_from_zero(Keyword.get(opts, :default_status, :unaffected))

    case status_change_entry(channel, version_type, boundaries) do
      nil -> flat_versions(channel, version_type, statused)
      entry -> %{"versions" => [entry], "issues" => []}
    end
  end

  # Under an `affected` default the entry has no lower bound to find: everything
  # below the introducing release is vulnerable too.
  defp open_from_zero(%{} = boundaries, :affected), do: %{boundaries | introduced: VersionComparator.zero()}

  defp open_from_zero(boundaries, _default_status), do: boundaries

  # An `unknown` default leaves every unlisted version unclaimed, so the releases
  # whose safety rests on the patch have to be stated. Containment alone, "this
  # release never held the introducing commit", is the proof such a record
  # declines to make.
  defp statused_ranges(ranges, opts) do
    fixed = Keyword.get(opts, :fixed_ranges, [])

    case Keyword.get(opts, :default_status, :unaffected) do
      :unknown -> [{ranges, "affected"}, {fixed, "unaffected"}]
      :affected -> [{fixed, "unaffected"}]
      _unaffected -> [{ranges, "affected"}]
    end
  end

  # A `pkg:otp` channel publishing OTP versions names one application, whose own
  # versions differ from the release's; every other channel already speaks its
  # package's vocabulary.
  #
  # The two ends resolve differently. A lower bound falls forward to the first
  # release that ships the application, since a flaw introduced before the
  # application existed still reaches it once it does: `tftp` split out of
  # `inets` long after some flaws were introduced. An upper bound is exact, as a
  # fix in a release that does not ship the application says nothing about that
  # application, and a later version would invent a fix it never had.
  defp lower_bound(%{purl_type: "otp", name: app}, :otp, version) when is_binary(app) do
    if version == VersionComparator.zero(),
      do: {:ok, version},
      else: OtpVersionsTable.first_shipped_version(version, app)
  end

  defp lower_bound(_channel, _version_type, version), do: {:ok, version}

  defp upper_bound(_channel, _version_type, :unbounded), do: {:ok, :unbounded}

  defp upper_bound(%{purl_type: "otp", name: app}, :otp, version) when is_binary(app) do
    OtpVersionsTable.app_version(version, app)
  end

  defp upper_bound(_channel, _version_type, version), do: {:ok, version}

  defp translation_issue(%{purl_type: "otp", name: app}, :otp) when is_binary(app) do
    "cannot resolve #{app}'s version for a range"
  end

  defp translation_issue(_channel, _version_type), do: nil

  defp flat_versions(channel, version_type, statused_ranges) do
    type = to_string(version_type)

    statused_ranges
    |> Enum.flat_map(fn {ranges, status} -> Enum.map(ranges, &{&1, status}) end)
    |> map_all(fn {range, status} ->
      with {:ok, translated} <- translate_range(channel, version_type, range) do
        {:ok, decorated_ranges(channel, [translated], type, status)}
      end
    end)
    |> case do
      {:ok, decorated} -> %{"versions" => Enum.concat(decorated), "issues" => []}
      :error -> %{"versions" => [], "issues" => [translation_issue(channel, version_type)]}
    end
  end

  defp translate_range(channel, version_type, %{from: from, until: until}) do
    with {:ok, from} <- lower_bound(channel, version_type, bare(from)),
         {:ok, until} <- upper_bound(channel, version_type, bare(until)) do
      {:ok, %{from: from, until: until}}
    end
  end

  defp map_all(items, fun) do
    items
    |> Enum.reduce_while([], fn item, acc ->
      case fun.(item) do
        {:ok, result} -> {:cont, [result | acc]}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      :error -> :error
      acc -> {:ok, Enum.reverse(acc)}
    end
  end

  defp status_change_entry(_channel, _version_type, nil), do: nil
  defp status_change_entry(_channel, _version_type, %{introduced: nil}), do: nil
  defp status_change_entry(_channel, _version_type, %{fixed: []}), do: nil
  defp status_change_entry(_channel, _version_type, %{open?: false}), do: nil

  # One fix needs no transition: `lessThan` states the same span, and states it
  # better. An open entry claims every version above the bound, including ones
  # not released yet, and a single fix on a branch can never close a line that
  # does not exist yet, so the open form would report tomorrow's release
  # affected. The bounded form claims only what was derived.
  defp status_change_entry(_channel, _version_type, %{fixed: [_only_one]}), do: nil

  defp status_change_entry(channel, version_type, boundaries) do
    %{introduced: introduced, fixed: fixed} = boundaries
    prefix = channel.tag_prefix || ""

    with {:ok, from} <- lower_bound(channel, version_type, bare(introduced)),
         {:ok, changes} <- map_all(fixed, &upper_bound(channel, version_type, bare(&1))) do
      %{
        "version" => prefix <> from,
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => to_string(version_type),
        "changes" => Enum.map(changes, &%{"at" => prefix <> &1, "status" => "unaffected"})
      }
    else
      :error -> nil
    end
  end

  ## ------------------------------------------------------------ git

  # The git-SHA ranges. Commit SHAs have no linear order, so a single fix renders
  # a bounded range and several a `changes[]` chain off the introducing commit.
  # Unreleased fixes still bound a git channel: the commit exists whether or not
  # a release contains it.
  #
  # A change backported to several branches introduces the flaw once per branch,
  # and a consumer walking the commit graph reaches only the commits descending
  # from the intro it was given. Each therefore states its own entry, or the
  # commits below the ones left out read as safe.
  defp git([], _fix_shas), do: %{"versions" => [], "issues" => ["the introduced boundary has no commit SHA"]}

  defp git(intro_shas, fix_shas) do
    %{"versions" => Enum.map(intro_shas, &git_entry(&1, fix_shas)), "issues" => []}
  end

  defp git_entry(intro, []), do: version_object(intro, "*", "git", "affected")
  defp git_entry(intro, [fix]), do: version_object(intro, fix, "git", "affected")

  defp git_entry(intro, fixes) do
    %{
      "version" => intro,
      "lessThan" => "*",
      "status" => "affected",
      "versionType" => "git",
      "changes" => Enum.map(fixes, &%{"at" => &1, "status" => "unaffected"})
    }
  end

  ## ------------------------------------------------------------ shared

  defp version_object(from, until, version_type, status) do
    %{
      "version" => from,
      "lessThan" => until,
      "status" => status,
      "versionType" => version_type
    }
  end

  defp bare(:unbounded), do: :unbounded
  defp bare("OTP-" <> rest), do: rest
  defp bare("OTP_" <> rest), do: rest

  defp bare("v" <> <<d, _::binary>> = tag) when d in ?0..?9, do: binary_part(tag, 1, byte_size(tag) - 1)

  defp bare(tag), do: tag
end
