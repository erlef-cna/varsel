# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveView.AffectedChecker do
  @moduledoc """
  Pure matching logic for the public CVE detail page's "Am I affected?"
  checker: given a raw CVE record's per-package `versions[]` (the exact data
  the page already renders — see `VarselWeb.CveHTML.affected_ranges/1`) and a
  visitor-typed version string, decides whether that version is affected,
  fixed, or never affected.

  Checker correctness is security-relevant: a wrong "not affected" verdict is
  the worst failure mode, so every branch here either proves a version is
  affected/fixed/unaffected from the data, or falls back to `:unparseable` —
  never a guess dressed up as a colored verdict.

  ## Scope

  Deliberately narrow: only `versionType in ["semver", "otp"]` ranges
  participate. Semver compares via the stdlib `Version` module; OTP compares
  its 4-segment release tags (`OTP-26.2.5.6`) lexicographically as integer
  tuples — nothing here reimplements range semantics that already exist
  elsewhere in the app. Every other `versionType` (`git`, `date`, custom
  schemes, …) is out of scope: `checkable?/1` excludes those ranges from
  consideration entirely, and a package with no semver/otp ranges at all
  isn't offered in the checker's package list.
  """

  @typedoc "A fix boundary paired with the branch label it's known by, if any (see `branch_label/2`)."
  @type fix :: %{raw: String.t(), branch_label: String.t() | nil}

  @type verdict ::
          {:empty}
          | {:unparseable}
          | {:affected, own_fix :: fix() | nil, other_fixes :: [fix()]}
          | {:fixed, via :: fix(), latest :: fix() | nil}
          | {:not_affected, intro :: String.t() | nil}

  @checkable_types ~w(semver otp)

  @doc "Whether a `versionType` this module knows how to compare."
  @spec supported_type?(String.t() | nil) :: boolean()
  def supported_type?(type), do: type in @checkable_types

  @doc """
  Parses a version string against a `versionType` ("semver" or "otp") into a
  comparable term, or `:error` on unparseable/unsupported input. Callers
  must treat `:error` as unparseable, never as "not affected".

  Semver parses via the stdlib `Version` module (short `major.minor` strings
  are zero-padded to a full `major.minor.patch` first — the CVE schema
  allows two-component versions `Version.parse/1` alone rejects). OTP tags
  strip an optional `OTP-` prefix and compare their dot-separated segments
  lexicographically as integers (`OTP-26.2.5.6` → `{26, 2, 5, 6}`, missing
  trailing segments zero-padded) — orderable, not semver-shaped.
  """
  @spec parse(String.t(), String.t()) :: Version.t() | tuple() | :error
  def parse(version, "semver") when is_binary(version) do
    case Version.parse(pad_semver(String.trim(version))) do
      {:ok, parsed} -> parsed
      :error -> :error
    end
  end

  def parse(version, "otp") when is_binary(version) do
    bare = version |> String.trim() |> strip_otp_prefix()

    case bare do
      "" ->
        :error

      <<c, _::binary>> when c not in ?0..?9 ->
        :error

      _valid ->
        bare |> String.split(".") |> dot_components_to_tuple()
    end
  end

  # Every dot component must be a bare integer; anything else is unparseable.
  defp dot_components_to_tuple(segments) do
    nums = Enum.map(segments, &clean_integer/1)

    if Enum.any?(nums, &is_nil/1), do: :error, else: List.to_tuple(pad4(nums))
  end

  defp clean_integer(segment) do
    case Integer.parse(segment) do
      {i, ""} -> i
      _partial_or_error -> nil
    end
  end

  def parse(_version, _type), do: :error

  defp pad4(nums) when length(nums) >= 4, do: Enum.take(nums, 4)
  defp pad4(nums), do: nums ++ List.duplicate(0, 4 - length(nums))

  defp strip_otp_prefix("OTP-" <> rest), do: rest
  defp strip_otp_prefix(other), do: other

  defp pad_semver(version) do
    case String.split(version, ".") do
      [_major] -> version <> ".0.0"
      [_major, _minor] -> version <> ".0"
      _full -> version
    end
  end

  @doc "Orderable comparison of two same-type parsed versions: `:lt` | `:eq` | `:gt`."
  @spec compare(Version.t() | tuple(), Version.t() | tuple()) :: :lt | :eq | :gt
  def compare(%Version{} = a, %Version{} = b), do: Version.compare(a, b)
  def compare(a, b) when is_tuple(a) and is_tuple(b) and a == b, do: :eq
  def compare(a, b) when is_tuple(a) and is_tuple(b), do: if(a < b, do: :lt, else: :gt)

  @doc """
  Whether an affected-entry's `versions[]` can be checked at all against a
  typed version string: at least one `status == "affected"` range whose
  `versionType` is semver or OTP.
  """
  @spec checkable?([map()]) :: boolean()
  def checkable?(versions) when is_list(versions) do
    versions
    |> Enum.filter(&(&1["status"] == "affected"))
    |> Enum.any?(&supported_type?(&1["versionType"]))
  end

  @doc """
  Matches a visitor-typed version string against one package's `versions[]`
  (the CVE record's own affected-entry array — same source the Affected
  card's range lines render from, already deduped by
  `VarselWeb.CveView.normalize_versions/1` upstream so this never sees a
  purl/git duplicate of a range under its canonical type). Returns a
  `verdict()`.

  Only semver/OTP `status == "affected"` ranges participate — everything
  else (`git`, `date`, …) is out of scope and the caller's job to gate out
  via `checkable?/1` before ever reaching here. When the record mixes
  version types the input is matched against BOTH comparators (each
  package's ranges are normally all one type in practice); a range whose own
  type the input can't parse under simply doesn't match.
  """
  @spec match(String.t(), [map()]) :: verdict()
  def match("", _versions), do: {:empty}
  def match(nil, _versions), do: {:empty}

  def match(input, versions) when is_list(versions) do
    ranges =
      versions
      |> Enum.filter(&(&1["status"] == "affected" and supported_type?(&1["versionType"])))
      |> Enum.map(&range_of/1)
      |> Enum.filter(& &1)

    parsed_inputs =
      ranges
      |> Enum.map(& &1.type)
      |> Enum.uniq()
      |> Map.new(&{&1, parse(input, &1)})

    if ranges != [] and Enum.all?(parsed_inputs, fn {_type, parsed} -> parsed == :error end) do
      {:unparseable}
    else
      classify(parsed_inputs, ranges)
    end
  end

  # One usable range: its versionType (the comparator to use), a parsed
  # lower bound, an ordered list of {parsed_at, status} transition points
  # (from lessThan/lessThanOrEqual and changes[], both normalized to
  # "becomes unaffected at this point"), the raw fix labels for display, the
  # release-line prefix a "fixed" verdict is allowed to extend into (see
  # `line_of/2`), and this range's own fix as a `fix()` (raw + branch label,
  # for the verdict-grammar tail — nil when the range is fully open).
  defp range_of(%{"version" => version, "versionType" => type} = entry) do
    case parse(version, type) do
      :error ->
        nil

      parsed_lower ->
        transitions = transitions_of(entry, type)
        # The range's OWN fix is its lowest transition — "fixed in" means the
        # first safe version of this line (VarselWeb.CveView.fix_boundary/1's
        # same ruling), not the last chained transition array-wise; the
        # ascending sort below already orders `transitions`, so the first
        # entry is the smallest.
        fix_raw = transitions |> List.first() |> then(&(&1 && &1.raw))

        %{
          type: type,
          lower: parsed_lower,
          lower_raw: version,
          transitions: transitions,
          line: line_of(type, transitions),
          fix:
            fix_raw &&
              %{raw: fix_raw, branch_label: VarselWeb.CveView.branch_label(fix_raw, type)}
        }
    end
  end

  defp range_of(_entry), do: nil

  # The leading segment(s) a "fixed" verdict must share with the range's own
  # fix boundary to count: this range only speaks for its own release line,
  # so a version from a DIFFERENT line entirely (a newer major a branched
  # record has no entry for, say) must not be waved through as "fixed" just
  # because it numerically exceeds this line's bound — that's the
  # gap-between-branches trap. OTP lines are keyed on the major only (OTP
  # majors are release lines on their own); semver keys on {major, minor},
  # mirroring `Varsel.Cases.Derivation.Platform.group_key/2`. No transition
  # (an open range) has no line boundary to guard, so it fixes nothing —
  # :affected stays unconditional for the whole tail. This guard is applied
  # ONLY when the package has more than one range (see `classify/2`) — with
  # a single range there is no sibling branch to protect against, so a
  # strictly-above-the-fix input on that one range must resolve to `:fixed`.
  defp line_of(_type, []), do: nil
  defp line_of("otp", [%{at: at} | _]), do: {elem(at, 0)}
  defp line_of("semver", [%{at: %Version{major: major, minor: minor}} | _]), do: {major, minor}

  # `strict?` marks whether the boundary version itself is still affected:
  # `lessThan: X` and a `changes[].at: X, status: unaffected` both mean
  # "affected while < X", so fixed starts exactly AT X (`strict?: false`,
  # `within?/2` uses `>=`). Only `lessThanOrEqual: X` includes X itself on
  # the affected side, so fixed starts strictly AFTER X (`strict?: true`,
  # `within?/2` uses `>`).
  defp bound_transition(raw, type, strict?) do
    case parse(raw, type) do
      :error -> []
      parsed -> [%{at: parsed, raw: raw, strict?: strict?}]
    end
  end

  defp transitions_of(entry, type) do
    from_bound =
      case entry do
        %{"lessThan" => lt} when lt not in [nil, "*"] ->
          bound_transition(lt, type, false)

        %{"lessThanOrEqual" => lte} when lte not in [nil, "*"] ->
          bound_transition(lte, type, true)

        _open ->
          []
      end

    from_changes =
      entry
      |> Map.get("changes", [])
      |> Enum.filter(&(&1["status"] == "unaffected"))
      |> Enum.map(fn %{"at" => at} ->
        case parse(at, type) do
          :error -> nil
          parsed -> %{at: parsed, raw: at, strict?: false}
        end
      end)
      |> Enum.filter(& &1)

    Enum.sort(from_bound ++ from_changes, &(compare(&1.at, &2.at) != :gt))
  end

  # Whichever range(s) the input falls inside decide the verdict; a version
  # below every range's lower bound (and not caught by any range) is not
  # affected. Ranges whose type couldn't parse the input (mixed-type
  # record) are skipped rather than erroring the whole match.
  #
  # Verdict-copy grammar (rev 3): an :affected verdict leads with the fix on
  # the user's OWN branch (the range they actually landed in) and lists
  # every OTHER range's fix as "also fixed in" — every fix, including the
  # leading one, carries its branch label. A :fixed verdict names the
  # "latest" fix (compared across every range's fix boundary, own type
  # only) so the caller can decide whether a "backported from" tail applies
  # (only when the matched fix isn't that latest fix).
  defp classify(_parsed_inputs, []), do: {:not_affected, nil}

  defp classify(parsed_inputs, ranges) do
    single_range? = length(ranges) == 1

    hits =
      ranges
      |> Enum.map(fn range ->
        case Map.get(parsed_inputs, range.type) do
          :error -> nil
          parsed_input -> {range, range_verdict(parsed_input, range, single_range?)}
        end
      end)
      |> Enum.filter(fn hit -> hit && elem(hit, 1) end)

    cond do
      own = Enum.find(hits, fn {_range, verdict} -> match?({:affected, _fix}, verdict) end) ->
        {own_range, _own_verdict} = own
        other_fixes = other_branch_fixes(ranges, own_range)
        {:affected, own_range.fix, other_fixes}

      fixed_hit = Enum.find(hits, fn {_range, verdict} -> match?({:fixed}, verdict) end) ->
        {matched_range, _fixed} = fixed_hit
        latest = latest_fix(ranges, matched_range.type)
        {:fixed, matched_range.fix, latest}

      true ->
        earliest_intro =
          ranges
          |> Enum.filter(&(Map.get(parsed_inputs, &1.type) != :error))
          |> Enum.min_by(& &1.lower, &(compare(&1, &2) != :gt), fn -> nil end)

        {:not_affected, earliest_intro && earliest_intro.lower_raw}
    end
  end

  # Every OTHER range's fix, distinct from the user's own matched range —
  # the "; also fixed in …" tail. Ranges with no fix (fully open) contribute
  # nothing to name.
  defp other_branch_fixes(ranges, own_range) do
    ranges
    |> Enum.reject(&(&1 == own_range))
    |> Enum.map(& &1.fix)
    |> Enum.filter(& &1)
    |> Enum.uniq()
  end

  # The greatest fix across every range of the given type — what a matched
  # fix is compared against to decide whether "backported from <latest>"
  # applies (only when the matched fix ISN'T the latest one).
  defp latest_fix(ranges, type) do
    ranges
    |> Enum.filter(&(&1.type == type and &1.fix))
    |> Enum.max_by(&parse(&1.fix.raw, type), &(compare(&1, &2) != :lt), fn -> nil end)
    |> case do
      nil -> nil
      range -> range.fix
    end
  end

  # Below this range's lower bound: not in range at all (no verdict from
  # this range — caller falls back to the global :not_affected).
  defp range_verdict(input, %{lower: lower} = range, single_range?) do
    if compare(input, lower) == :lt do
      nil
    else
      range_verdict_within(input, range, single_range?)
    end
  end

  defp range_verdict_within(_input, %{transitions: []}, _single_range?), do: {:affected, nil}

  defp range_verdict_within(input, %{transitions: transitions, line: line}, single_range?) do
    # The last transition at or before the input decides the current status;
    # none met yet means the input still sits in the still-affected head of
    # the range. A "fixed" verdict only applies while the input is still on
    # this range's own release line — past that, this range has nothing to
    # say (see `line_of/2`) UNLESS it's the package's only range, in which
    # case there's no sibling branch for the input to have fallen into a
    # gap of, so a strictly-above-the-fix input always resolves to :fixed.
    case Enum.filter(transitions, &within?(input, &1)) do
      [] ->
        {:affected, transitions |> List.first() |> Map.get(:raw)}

      _met when single_range? ->
        {:fixed}

      _met ->
        if same_line?(input, line), do: {:fixed}
    end
  end

  defp same_line?(input, line), do: line_of_input(input) == line

  defp line_of_input(%Version{major: major, minor: minor}), do: {major, minor}
  defp line_of_input(otp) when is_tuple(otp), do: {elem(otp, 0)}

  defp within?(input, %{at: at, strict?: true}), do: compare(input, at) == :gt
  defp within?(input, %{at: at, strict?: false}), do: compare(input, at) != :lt
end
