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

  The order is the version scheme's own, and `compare/2` delegates it to
  `:varsel_versions`, OTP's implementation. It is partial: a version orders
  against its ancestors and descendants, and `:nc` against everything else.

  Pre-releases and the `OTP-` prefix are this module's own, since the OTP
  implementation takes neither.

  A patch may be merged forward, at a point the version number does not record.
  In erlang/otp, `22.3.4.12.1` is contained in `24.0` and every later release,
  but in nothing in 23.x. Only the commit graph answers that, so `:nc` means the
  scheme does not order the two, never that no ancestry exists.

  Callers that need one line, such as sorting a timeline or cutting it into
  ranges, use `total_compare/2`. Callers deciding whether one version implies
  another must respect `:nc`.
  """

  # TODO: Switch to `:versions` from runtime_tools and delete `src/varsel_versions.erl`
  # once an OTP release ships erlang/otp PR #11556.

  @enforce_keys [:segments, :prerelease?, :raw]
  defstruct [:segments, :prerelease?, :raw]

  @type t :: %__MODULE__{
          segments: [non_neg_integer()],
          prerelease?: boolean(),
          raw: String.t()
        }

  # `<Major>.<Minor>[.<Patch>...]`, optionally a release candidate. `-rc<N>` is
  # the only suffix the scheme allows. Anchored, so a tag carrying anything else
  # is not a version: the R series, `nightly`, a date, a semver tag in an OTP
  # repo. The numeric part is only shaped here; `:varsel_versions.list_check/1`
  # is what accepts or rejects it.
  @release ~r/\A(\d+(?:\.\d+)+)(?:-rc(\d+))?\z/

  @doc "Parses an OTP version string. `:error` for non-release tags."
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(version) when is_binary(version) do
    with [_, numeric | rc] <- Regex.run(@release, strip_prefix(version)),
         segments = Enum.map(String.split(numeric, "."), &String.to_integer/1),
         true <- :varsel_versions.list_check(segments) do
      {:ok, %__MODULE__{segments: segments, prerelease?: rc != [], raw: version}}
    else
      _ -> :error
    end
  end

  @doc """
  Compares two OTP versions (strings or structs), per the version scheme's
  partial order: `:lt` | `:eq` | `:gt`, or `:nc` when the two lie on branches
  that never meet.

  A caller reducing a set of boundaries must treat `:nc` as "neither implies the
  other" rather than as false.
  """
  @spec compare(String.t() | t(), String.t() | t()) :: :lt | :eq | :gt | :nc
  def compare(left, right) do
    case {parse_any(left), parse_any(right)} do
      {{:ok, a}, {:ok, b}} -> compare_parsed(a, b)
      # A non-release bounds no range, so the only requirement is that it never
      # displaces one that does: it sorts above every release, as in `sort_key/1`.
      _ -> total_compare(left, right)
    end
  end

  # The scheme orders the numeric parts; a pre-release sits just below the
  # release it leads to, which only matters once those parts are equal.
  defp compare_parsed(%{segments: same} = a, %{segments: same} = b) do
    case {a.prerelease?, b.prerelease?} do
      {x, x} -> :eq
      {true, false} -> :lt
      {false, true} -> :gt
    end
  end

  defp compare_parsed(a, b) do
    case :varsel_versions.list_compare(a.segments, b.segments) do
      :same -> :eq
      :ancestor -> :lt
      :descendant -> :gt
      :undefined -> :nc
    end
  end

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

  defp parse_any(%__MODULE__{} = version), do: {:ok, version}
  defp parse_any(version) when is_binary(version), do: parse(version)

  # `{rank, segments, release_rank}`: rank 0 for a release, 1 for anything that
  # is not one, so a non-release sorts last and never bounds a real range. A
  # release ranks above its pre-releases.
  defp sort_key(version) do
    case parse_any(version) do
      {:ok, v} -> {0, v.segments, if(v.prerelease?, do: 0, else: 1)}
      :error -> {1, [], 0}
    end
  end

  defp strip_prefix("OTP-" <> rest), do: rest
  defp strip_prefix("OTP_" <> rest), do: rest
  defp strip_prefix(version), do: version
end
