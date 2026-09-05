# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.OTPVersion do
  @moduledoc """
  Parses and orders Erlang/OTP release versions, in the shape of Elixir's
  `Version`.

  Versions are the numeric releases, `17.0` and up: `27.0`, `27.3.4.3`.
  `OTP-`/`OTP_` prefixes are stripped first, so `OTP-27.0` and `27.0` parse
  identically. A version has at least two dot-separated parts and no suffix;
  see the [version scheme](https://www.erlang.org/doc/system/versions.html).
  Release candidates (`29.0-rc1`), the R series (`R16B03-1`) and topic tags
  (`R16B03_yielding_binary_to_term`) are non-release tags: `parse/1` returns
  `:error`, and the comparison functions raise.

  ## Ordering

  The order is the version scheme's own, and `compare/2` delegates it to
  `:varsel_versions`, OTP's implementation. It is partial: a version orders
  against its ancestors and descendants, and `:nc` against everything else.

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

  @enforce_keys [:segments, :raw]
  defstruct [:segments, :raw]

  @type t :: %__MODULE__{
          segments: [non_neg_integer()],
          raw: String.t()
        }

  # `<Major>.<Minor>[.<Patch>...]`, anchored. The numeric part is only shaped
  # here; `:varsel_versions.list_check/1` is what accepts or rejects it.
  @release ~r/\A\d+(?:\.\d+)+\z/

  @doc "Parses an OTP version string. `:error` for non-release tags."
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(version) when is_binary(version) do
    with [numeric] <- Regex.run(@release, strip_prefix(version)),
         segments = Enum.map(String.split(numeric, "."), &String.to_integer/1),
         true <- :varsel_versions.list_check(segments) do
      {:ok, %__MODULE__{segments: segments, raw: version}}
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

  Raises `ArgumentError` for a non-release; callers filter with `release?/1`
  first.
  """
  @spec compare(String.t() | t(), String.t() | t()) :: :lt | :eq | :gt | :nc
  def compare(left, right) do
    case :varsel_versions.list_compare(segments!(left), segments!(right)) do
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

  Raises `ArgumentError` for a non-release; callers filter with `release?/1`
  first.
  """
  @spec total_compare(String.t() | t(), String.t() | t()) :: :lt | :eq | :gt
  def total_compare(left, right) do
    a = segments!(left)
    b = segments!(right)

    cond do
      a < b -> :lt
      a > b -> :gt
      true -> :eq
    end
  end

  @doc "Whether `version` names a real release (not a topic/feature tag)."
  @spec release?(String.t()) :: boolean()
  def release?(version), do: match?({:ok, _}, parse(version))

  @doc "Whether `version` is a pre-release. The scheme has none."
  @spec prerelease?(String.t()) :: boolean()
  def prerelease?(_version), do: false

  ## ------------------------------------------------------------ internals

  defp segments!(%__MODULE__{segments: segments}), do: segments

  defp segments!(version) when is_binary(version) do
    case parse(version) do
      {:ok, %__MODULE__{segments: segments}} -> segments
      :error -> raise ArgumentError, "not an OTP version: #{inspect(version)}"
    end
  end

  defp strip_prefix("OTP-" <> rest), do: rest
  defp strip_prefix("OTP_" <> rest), do: rest
  defp strip_prefix(version), do: version
end
