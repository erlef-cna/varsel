# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.OTPVersion do
  @moduledoc """
  Parses and orders Erlang/OTP release versions, in the shape of Elixir's
  `Version`.

  Versions are the numeric releases, `17.0` and up: `27.3.4.3`, `29.0-rc1`.
  `OTP-`/`OTP_` prefixes are stripped first, so `OTP-27.0` and `27.0` parse
  identically. A version has at least two dot-separated parts, and `-rc<N>` is
  its only suffix; see the [version scheme](https://www.erlang.org/doc/system/versions.html).

  The legacy R series (`R6B-0` … `R16B03-1`) is **not** a version here.
  `parse/1` returns `:error` for it, as it does for topic/feature tags such as
  `R16B03_yielding_binary_to_term`, so an R tag neither bounds a derived range
  nor orders against a numeric one.

  Pre-releases order below the release of the same number (`29.0-rc1` < `29.0`).

  ## Ordering

  `<Major>.<Minor>.<Patch>` names a release on the main track, and those are
  totally ordered. A fourth part or beyond hangs a maintenance patch off the
  version its earlier parts name, and branching is recursive: `18.2.4.0.1`
  hangs off `18.2.4.0`, which hangs off `18.2.4`.

  A patch contains the version it hangs off, so it orders against that version
  and everything at or below it, and against other patches of the same version.
  Against a main-track release *above* the version it hangs off, `compare/2`
  returns `:nc`.

  A patch may be merged forward, at a point the version number does not record.
  In erlang/otp, `17.5.6.1` is an ancestor of `18.1` but not of `18.0`,
  `17.5.6.10` reaches nothing before `21.2`, and `22.3.4.12.1` was never merged
  forward at all. Versions of identical shape differ, so only the commit graph
  answers that question.

  Callers that need one line, such as sorting a timeline or cutting it into
  ranges, use `total_compare/2`. Callers deciding whether one version implies
  another must respect `:nc`.
  """

  @enforce_keys [:segments, :prerelease?, :raw]
  defstruct [:segments, :prerelease?, :raw]

  @type t :: %__MODULE__{
          segments: [integer()],
          prerelease?: boolean(),
          raw: String.t()
        }

  # `<Major>.<Minor>[.<Patch>...]`, optionally a release candidate. Two parts is
  # the minimum the version scheme allows, since less significant parts are
  # omitted only when they are 0, and `-rc<N>` is its only suffix. Anchored, so
  # a tag carrying anything else is not a version: the R series, `nightly`, a
  # date, a semver tag in an OTP repo.
  @release ~r/\A(\d+(?:\.\d+)+)(?:-rc(\d+))?\z/

  # `<Major>.<Minor>.<Patch>`.
  @normal_parts 3

  @doc "Parses an OTP version string. `:error` for non-release tags."
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(version) when is_binary(version) do
    case Regex.run(@release, strip_prefix(version)) do
      [_, numeric] -> {:ok, build(numeric, false, version)}
      [_, numeric, _rc] -> {:ok, build(numeric, true, version)}
      nil -> :error
    end
  end

  defp build(numeric, prerelease?, version) do
    segments = numeric |> String.split(".") |> Enum.map(&String.to_integer/1)

    %__MODULE__{segments: segments, prerelease?: prerelease?, raw: version}
  end

  @doc """
  Compares two OTP versions (strings or structs), per the version scheme's
  partial order: `:lt` | `:eq` | `:gt`, or `:nc` when the two lie on branches
  that never meet.

  A caller reducing a set of boundaries must treat `:nc` as "neither implies the
  other" rather than as false.
  """
  @spec compare(String.t() | t(), String.t() | t()) :: :lt | :eq | :gt | :nc
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def compare(left, right) do
    a = segments_of(left)
    b = segments_of(right)

    cond do
      trunk?(a) and trunk?(b) -> total_compare(left, right)
      prefix?(a, b) -> :lt
      prefix?(b, a) -> :gt
      not trunk?(a) and not trunk?(b) and base(a) == base(b) -> total_compare(left, right)
      not trunk?(a) and trunk?(b) and under_ancestry?(b, a) -> :gt
      not trunk?(b) and trunk?(a) and under_ancestry?(a, b) -> :lt
      true -> :nc
    end
  end

  defp trunk?(segments), do: length(segments) <= @normal_parts

  # Whether `version` is at or below some version `branch` descends from. The
  # ancestry is the whole chain, not just the immediate base: `17.0.0.1.1`
  # descends from `17.0.0.1` and so outranks its sibling `17.0.0.0`.
  # A pre-release of a version the patch hangs off is below it either way, so
  # segment order settles this.
  defp under_ancestry?(version, branch) do
    Enum.any?(ancestry(branch), &(version <= &1))
  end

  defp ancestry(segments) when length(segments) > @normal_parts do
    parent = base(segments)
    [parent | ancestry(parent)]
  end

  defp ancestry(_segments), do: []

  @doc """
  Whether the scheme orders every pair of versions. OTP's does not: a branch
  version and a release above its base have no order between them.
  """
  @spec total_order?() :: boolean()
  def total_order?, do: false

  @doc """
  Whether the version scheme orders these two at all. False for versions on
  branches that never meet (`27.3.4.15` and `28.0`).
  """
  @spec comparable?(String.t() | t(), String.t() | t()) :: boolean()
  def comparable?(left, right) do
    compare(left, right) != :nc
  end

  @doc """
  Compares on one line, ordering incomparable versions by their segments so a
  timeline can be sorted. `sort/3` and range-cutting want this; a caller
  deciding implication wants `compare/2`.
  """
  @spec total_compare(String.t() | t(), String.t() | t()) :: :lt | :eq | :gt
  def total_compare(left, right) do
    ka = sort_key(left)
    kb = sort_key(right)

    cond do
      ka < kb -> :lt
      ka > kb -> :gt
      true -> :eq
    end
  end

  @doc "Whether `version` names a real release (not a topic/feature tag)."
  @spec release?(String.t()) :: boolean()
  def release?(version), do: match?({:ok, _}, parse(version))

  @doc "Whether `version` is a pre-release (a `-suffix` release candidate)."
  @spec prerelease?(String.t()) :: boolean()
  def prerelease?(version) do
    case parse(version) do
      {:ok, v} -> v.prerelease?
      :error -> false
    end
  end

  ## ------------------------------------------------------------ internals

  # Branching is recursive: `18.2.4.0.1` branches from `18.2.4.0`, which itself
  # branches from `18.2.4`. A branch's base is therefore all but its last part,
  # never a truncation to the normal three.
  defp base(segments) when length(segments) > @normal_parts do
    Enum.drop(segments, -1)
  end

  defp base(segments), do: segments

  defp prefix?(a, b), do: length(a) < length(b) and Enum.take(b, length(a)) == a

  defp segments_of(%__MODULE__{segments: segments}), do: segments

  defp segments_of(version) when is_binary(version) do
    case parse(version) do
      {:ok, v} -> v.segments
      :error -> []
    end
  end

  # `{rank, segments, release_rank}`: rank 0 for a release, 1 for anything that
  # is not one, so a non-release sorts last and never bounds a real range. A
  # release ranks above its pre-releases.
  defp sort_key(%__MODULE__{} = v), do: {0, v.segments, if(v.prerelease?, do: 0, else: 1)}

  defp sort_key(version) when is_binary(version) do
    case parse(version) do
      {:ok, v} -> sort_key(v)
      :error -> {1, [], 0}
    end
  end

  defp strip_prefix("OTP-" <> rest), do: rest
  defp strip_prefix("OTP_" <> rest), do: rest
  defp strip_prefix(version), do: version
end
