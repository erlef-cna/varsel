# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.VersionResolution do
  @moduledoc """
  Answers "what does this record say about version V of this product?" by the
  algorithm CVE Record Format 5.1 specifies for `affected[].versions[]`.

  The schema does not leave this to interpretation — it prints the algorithm in
  the `versions` property description, and this module implements exactly that:

      for entry in product.versions {
        if entry.lessThan absent and entry.lessThanOrEqual absent and v == entry.version {
          return entry.status
        }
        if (lessThan present and entry.version <= v < entry.lessThan) or
           (lessThanOrEqual present and entry.version <= v <= entry.lessThanOrEqual) {
          status = entry.status
          for change in entry.changes {
            if change.at <= v { status = change.status }
          }
          return status
        }
      }
      return product.defaultStatus

  Three consequences worth stating, because they are easy to get wrong:

    * The **first matching entry wins** — the algorithm returns from inside the
      loop. Later entries covering the same version are not consulted.
    * `changes` are applied **in array order**, each one overwriting the last.
      They are not sorted, and a record may legitimately move a version back to
      `affected` after an `unaffected` transition.
    * The answer is a *status*, one of `:affected`, `:unaffected`, `:unknown` —
      not a boolean. `:unknown` is a real answer meaning the record does not
      say, and must never be reported as safe.

  ## `changes[]` is temporarily not resolved

  Our own published records use `changes[]` to mean "one fix per release line",
  which the spec does not: transitions apply in array order across the entire
  range, so a chain fixed at `27.3.4` and `28.7.6` answers "unaffected" for
  `28.0.0`. Resolving those records exactly as specified would therefore hand
  out wrong "not affected" answers, so any entry carrying `changes[]` makes its
  product `{:error, :unsupported}` and the checker declines to answer.

  This is a data problem, not an algorithm one — see the temporary clause in
  `comparable_entries/1`. The display is unaffected and still shows every
  transition.

  ## All-or-nothing parsing

  A package resolves only if **every** boundary that could be consulted parses
  under its entry's `versionType`. A partially-understood product silently
  understates its affected span: a record bounded `R13B03 → 27.3.4.15` answers
  "unaffected" for every version in that range if the unparseable bound is
  dropped, which is a false negative — the worst answer this code can give. When
  anything is unparseable the whole product returns `{:error, :unsupported}` and
  the caller declines to answer at all.
  """

  alias Varsel.Cases.Reachability.VersionComparator

  @type status :: :affected | :unaffected | :unknown
  @type error :: :unparseable | :unsupported

  # The version schemes we can order:
  #
  #   * `semver` — via Elixir's `Version`, incl. pre-release precedence
  #   * `otp` — the numeric releases, 17.0 and up
  #   * `date` — `YYYY-MM-DD`, as hosted services version themselves
  #
  # Everything else (git shas, `custom`, vendor strings) has no ordering we
  # could apply, so a product using it can only be shown, never queried.
  @supported_types ~w(semver otp date)

  @doc "Whether a `versionType` this module can order."
  @spec supported_type?(term()) :: boolean()
  def supported_type?(type), do: type in @supported_types

  @doc """
  Whether this product can be asked about a version at all — the question a UI
  must answer *before* offering an input, rather than discovering by trying.

  False for a product whose entries this module cannot order end to end: git
  shas, dates, vendor strings, or a boundary that won't parse under its own
  declared scheme. Such a product can only be shown, not queried, so the caller
  hides the input instead of taking a version it could never answer.

  True says the entries are orderable, not that any particular input will be —
  a typed string that isn't a version still comes back
  `{:error, :unparseable}` from `resolve/3`.
  """
  @spec resolvable?([map()]) :: boolean()
  def resolvable?(versions) when is_list(versions) do
    match?({:ok, [_ | _]}, comparable_entries(versions))
  end

  @doc """
  The status a product's `versions[]` assigns to `input`.

    * `{:ok, status}` — the record answers, via a matching entry or by falling
      through to `default_status`. One of `:affected`, `:unaffected`,
      `:unknown`; `:unknown` is a real answer meaning the record does not say,
      and must never be reported as safe.
    * `{:error, :unparseable}` — `input` is not a version in any scheme the
      product's entries use (someone typed `latest`, or a semver-declared
      product was asked about an OTP tag). The caller must not read this as
      "unaffected".
    * `{:error, :unsupported}` — the product itself cannot be ordered. Callers
      that gate on `resolvable?/1` never see this.

  `default_status` is the entry's `defaultStatus`; per the schema it defaults to
  `unknown` when absent, since a record that lists only affected ranges has said
  nothing about anything else.

  Note there is deliberately no "fixed" answer. With arbitrary per-entry
  statuses and an arbitrary default, "was this version affected further back?"
  has no general answer — the record states a status per version, and that is
  all this returns.
  """
  @spec resolve([map()], String.t() | nil, String.t()) :: {:ok, status()} | {:error, error()}
  def resolve(versions, default_status, input) when is_list(versions) and is_binary(input) do
    with {:ok, entries} <- comparable_entries(versions) do
      resolve_against(entries, cast_status(default_status), input)
    end
  end

  # With no entries the schema's loop never runs: the default is the answer, and
  # there is no version scheme the input could even be parsed under.
  defp resolve_against([], default_status, _input), do: {:ok, default_status}

  defp resolve_against(entries, default_status, input) do
    with {:ok, inputs} <- parse_input(input, entries) do
      {:ok, walk(entries, inputs, default_status)}
    end
  end

  ## ------------------------------------------------------------- the algorithm

  # Schema order is significant: the first entry covering `input` answers.
  # `inputs` holds the input normalized per version scheme; an entry whose
  # scheme the input doesn't parse under simply cannot cover it.
  defp walk([], _inputs, default_status), do: default_status

  defp walk([entry | rest], inputs, default_status) do
    case Map.fetch(inputs, entry.kind) do
      {:ok, input} ->
        case entry_status(entry, input) do
          :no_match -> walk(rest, inputs, default_status)
          status -> status
        end

      :error ->
        walk(rest, inputs, default_status)
    end
  end

  # An entry with no upper bound describes exactly one version.
  defp entry_status(%{lower: lower, upper: nil} = entry, input) do
    if compare(entry, input, lower) == :eq, do: entry.status, else: :no_match
  end

  defp entry_status(%{lower: lower, upper: upper} = entry, input) do
    if compare(entry, input, lower) != :lt and within_upper?(entry, input, upper) do
      apply_changes(entry, input)
    else
      :no_match
    end
  end

  # An open range has no upper bound to fail against.
  defp within_upper?(_entry, _input, :unbounded), do: true

  defp within_upper?(%{upper_inclusive?: true} = entry, input, upper), do: compare(entry, input, upper) != :gt

  defp within_upper?(entry, input, upper), do: compare(entry, input, upper) == :lt

  # `changes` refine the entry's status in ARRAY order — each transition at or
  # below the input overwrites the previous answer, so a record can move a
  # version back to affected after an unaffected transition.
  defp apply_changes(entry, input) do
    Enum.reduce(entry.changes, entry.status, fn change, status ->
      if compare(entry, input, change.at) == :lt, do: status, else: change.status
    end)
  end

  # "By convention, typically 0 denotes the earliest possible version" (schema).
  # It has to sort below everything, which a scheme's own parser will not
  # necessarily do on its own.
  defp compare(_entry, :zero, :zero), do: :eq
  defp compare(_entry, :zero, _other), do: :lt
  defp compare(_entry, _other, :zero), do: :gt
  defp compare(%{kind: :date}, a, b), do: Date.compare(a, b)
  defp compare(%{kind: kind}, a, b), do: VersionComparator.compare(kind, a, b)

  ## --------------------------------------------------------------- preparation

  # Every entry, in schema order, reduced to what the algorithm needs.
  #
  # A range whose TYPE has no ordering (a git-sha or date range beside the
  # semver ones — the same vulnerability restated in another vocabulary) is
  # skipped: a typed semver or OTP version could never fall inside it, so it
  # could only ever have answered "no match" anyway.
  #
  # A range of a type we DO order but whose boundary won't parse is fatal for
  # the whole product. That is the false-negative case: dropping it would leave
  # the versions it covers answered by some later entry, or by the default,
  # understating the affected span.
  defp comparable_entries(versions) do
    Enum.reduce_while(versions, {:ok, []}, fn version, {:ok, acc} ->
      cond do
        not supported_type?(version["versionType"]) ->
          {:cont, {:ok, acc}}

        # TEMPORARY — remove this clause once the published records are fixed.
        #
        # Our own legacy records use `changes[]` to mean "a fix per release
        # line", which is not what it means. The schema applies transitions in
        # array order across the WHOLE range, so an entry open from 26.0 with
        # transitions at 27.3.4 and 28.7.6 answers "unaffected" for 28.0.0 —
        # 27.3.4 is below it and wins — when 28.0.0 is in fact affected until
        # its own line's 28.7.6.
        #
        # Resolving these correctly-per-spec would therefore report a wrong
        # "not affected" for real versions, so the whole product declines
        # instead. The DISPLAY still shows every transition; only the checker
        # stays silent. 75 of 316 corpus entries carry this shape.
        version["changes"] not in [nil, []] ->
          {:halt, {:error, :unsupported}}

        entry = comparable_entry(version) ->
          {:cont, {:ok, acc ++ [entry]}}

        true ->
          {:halt, {:error, :unsupported}}
      end
    end)
  end

  # `nil` when a boundary of an otherwise-supported type won't parse.
  defp comparable_entry(version) do
    type = version["versionType"]

    kind = String.to_existing_atom(type)

    with {:ok, lower} <- normalize(version["version"], kind),
         {:ok, upper, inclusive?} <- upper_bound(version, kind),
         {:ok, changes} <- changes(version, kind) do
      %{
        kind: kind,
        lower: lower,
        upper: upper,
        upper_inclusive?: inclusive?,
        status: cast_status(version["status"]),
        changes: changes
      }
    else
      _unparseable_boundary -> nil
    end
  end

  # `lessThan: "*"` is an open range, not a bound: the entry covers everything
  # from its lower bound up, and its `changes` do the rest of the work.
  defp upper_bound(%{"lessThan" => "*"}, _kind), do: {:ok, :unbounded, false}

  defp upper_bound(%{"lessThan" => less_than}, kind) when is_binary(less_than) do
    with {:ok, bound} <- normalize(less_than, kind), do: {:ok, bound, false}
  end

  defp upper_bound(%{"lessThanOrEqual" => "*"}, _kind), do: {:ok, :unbounded, true}

  defp upper_bound(%{"lessThanOrEqual" => lte}, kind) when is_binary(lte) do
    with {:ok, bound} <- normalize(lte, kind), do: {:ok, bound, true}
  end

  # Neither bound: a single-version entry.
  defp upper_bound(_version, _kind), do: {:ok, nil, false}

  defp changes(version, kind) do
    version
    |> Map.get("changes")
    |> List.wrap()
    |> Enum.reduce_while({:ok, []}, fn change, {:ok, acc} ->
      case normalize(change["at"], kind) do
        {:ok, at} -> {:cont, {:ok, acc ++ [%{at: at, status: cast_status(change["status"])}]}}
        :error -> {:halt, :error}
      end
    end)
  end

  # The input must parse under at least one scheme the product uses, and is kept
  # normalized PER scheme: an entry always compares it under its own
  # `versionType`, never under a sibling entry's.
  defp parse_input(input, entries) do
    normalized =
      for kind <- entries |> Enum.map(& &1.kind) |> Enum.uniq(),
          {:ok, value} <- [normalize(input, kind)],
          into: %{},
          do: {kind, value}

    if normalized == %{}, do: {:error, :unparseable}, else: {:ok, normalized}
  end

  # A boundary is usable only if its own scheme can order it. Short semver
  # (`1.5`) is zero-padded first: the CVE schema allows two-component versions
  # and people type them, while the tag parser behind `VersionComparator`
  # deliberately does not.
  defp normalize(nil, _kind), do: :error

  defp normalize(value, kind) when is_binary(value) do
    case String.trim(value) do
      # The "earliest possible version" sentinel is a convention about the
      # bound, not the scheme: a date range opens with it too (hex.pm's
      # `0 → 2026-03-10` in CVE-2026-90015).
      "0" -> {:ok, :zero}
      trimmed -> normalize_bound(trimmed, kind)
    end
  end

  defp normalize(_value, _kind), do: :error

  # Dates are `YYYY-MM-DD` and compare as dates, not as strings.
  defp normalize_bound(value, :date) do
    case Date.from_iso8601(value) do
      {:ok, date} -> {:ok, date}
      {:error, _reason} -> :error
    end
  end

  defp normalize_bound(value, kind) do
    padded = pad(value, kind)

    case VersionComparator.parse(kind, padded) do
      {:ok, _parsed} -> {:ok, padded}
      :error -> :error
    end
  end

  defp pad(value, :semver) do
    bare = String.replace_prefix(value, "v", "")

    case bare |> String.split("-", parts: 2) |> hd() |> String.split(".") do
      [_major] -> bare <> ".0.0"
      [_major, _minor] -> bare <> ".0"
      _full -> bare
    end
  end

  defp pad(value, :otp), do: value

  # An absent status is `unknown`, not a guess in either direction.
  defp cast_status("affected"), do: :affected
  defp cast_status("unaffected"), do: :unaffected
  defp cast_status(_absent_or_unknown), do: :unknown
end
