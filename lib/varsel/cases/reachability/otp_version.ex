# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.OTPVersion do
  @moduledoc """
  Parses and orders Erlang/OTP release versions, in the shape of Elixir's
  `Version`.

  Versions are the numeric releases, `17.0` and up: `27.3.4.3`, `29.0-rc1`.
  `OTP-`/`OTP_` prefixes are stripped first, so `OTP-27.0` and `27.0` parse
  identically.

  The legacy R series (`R6B-0` … `R16B03-1`) is **not** a version here.
  `parse/1` returns `:error` for it, as it does for topic/feature tags such as
  `R16B03_yielding_binary_to_term`, so an R tag neither bounds a derived range
  nor orders against a numeric one.

  Pre-releases order below the release of the same number (`29.0-rc1` < `29.0`).
  """

  @enforce_keys [:segments, :prerelease?, :raw]
  defstruct [:segments, :prerelease?, :raw]

  @type t :: %__MODULE__{
          segments: [integer()],
          prerelease?: boolean(),
          raw: String.t()
        }

  # An R-series tag or a topic tag built on one. Matched to be rejected, so an
  # `R16B03` neither parses as a version nor falls through to the numeric
  # parser, which would read its digits and order it among the numeric releases.
  @r_series ~r/\AR\d/

  @doc "Parses an OTP version string. `:error` for non-release tags."
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(version) when is_binary(version) do
    bare = strip_prefix(version)

    if Regex.match?(@r_series, bare), do: :error, else: parse_modern(bare, version)
  end

  defp parse_modern(bare, version) do
    {numeric, suffix} = split_suffix(bare)

    case numeric_segments(numeric) do
      [] ->
        :error

      segments ->
        {:ok,
         %__MODULE__{
           segments: segments,
           prerelease?: suffix != "",
           raw: version
         }}
    end
  end

  @doc "Compares two OTP versions (strings or structs): `:lt` | `:eq` | `:gt`."
  @spec compare(String.t() | t(), String.t() | t()) :: :lt | :eq | :gt
  def compare(left, right) do
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

  defp split_suffix(bare) do
    case String.split(bare, "-", parts: 2) do
      [n] -> {n, ""}
      [n, s] -> {n, s}
    end
  end

  defp numeric_segments(numeric) do
    numeric
    |> String.split(".")
    |> Enum.flat_map(fn part ->
      case Integer.parse(part) do
        {i, ""} -> [i]
        _ -> []
      end
    end)
  end
end
