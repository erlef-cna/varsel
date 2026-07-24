# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.OTPVersion do
  @moduledoc """
  Parses and orders Erlang/OTP release versions, in the shape of Elixir's
  `Version`.

  OTP has two eras. `OTP-`/`OTP_` prefixes are stripped first, so `OTP-27.0` and
  `27.0` parse identically.

    * **modern** — numeric (`17.0` and up), e.g. `27.3.4.3`, `29.0-rc1`.
    * **legacy R-series** — `R13B03` … `R16B03-1`, optionally with an RC marker
      (`R16A_RELEASE_CANDIDATE`, `R16B01_RC1`). Every R release orders *below*
      every modern one (R16 preceded 17.0). A `release line` is `{:r, major,
      letter}` (e.g. `R13B`); modern lines are the `major` integer.

  Topic/feature tags such as `R16B03_yielding_binary_to_term` are not release
  versions — `parse/1` returns `:error` for them.

  Pre-releases order below the release of the same number (`29.0-rc1` < `29.0`;
  `R16A_RELEASE_CANDIDATE` < `R16A`).
  """

  @enforce_keys [:era, :segments, :prerelease?, :raw]
  defstruct [:era, :segments, :prerelease?, :raw]

  @type t :: %__MODULE__{
          era: 0 | 1,
          segments: [integer()],
          prerelease?: boolean(),
          raw: String.t()
        }

  # Era discriminators so one Erlang term order sorts legacy below modern.
  @r_era 0
  @modern_era 1

  @doc "Parses an OTP version string. `:error` for non-release tags."
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(version) when is_binary(version) do
    bare = strip_prefix(version)

    case r_parts(bare) do
      {:ok, major, letter, minor, patch, rc?} ->
        {:ok,
         %__MODULE__{
           era: @r_era,
           segments: [major, letter_rank(letter), minor, patch],
           prerelease?: rc?,
           raw: version
         }}

      :error ->
        parse_modern(bare, version)
    end
  end

  defp parse_modern(bare, version) do
    {numeric, suffix} = split_suffix(bare)

    case numeric_segments(numeric) do
      [] ->
        :error

      segments ->
        {:ok,
         %__MODULE__{
           era: @modern_era,
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

  @doc "Whether `version` is a pre-release (a modern `-suffix` or an R-series RC)."
  @spec prerelease?(String.t()) :: boolean()
  def prerelease?(version) do
    case parse(version) do
      {:ok, v} -> v.prerelease?
      :error -> false
    end
  end

  ## ------------------------------------------------------------ internals

  # `{era, segments, release_rank}`: lower era (R) first; a release ranks above
  # its pre-releases.
  defp sort_key(%__MODULE__{} = v), do: {v.era, v.segments, if(v.prerelease?, do: 0, else: 1)}

  defp sort_key(version) when is_binary(version) do
    case parse(version) do
      {:ok, v} -> sort_key(v)
      # Not a release: sort last so it never bounds a real range.
      :error -> {@modern_era + 1, [], 2}
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

  # A real R-series release: R<major><letter>[<minor>][-<patch>] optionally
  # followed by an RC marker. A trailing non-RC word makes it a topic tag
  # (:error). `Regex.run` drops trailing empty groups, so pad to 6.
  defp r_parts(bare) do
    rx = ~r/\AR(\d+)([A-Z])(\d*)(?:-(\d+))?(_RC\d+|_RELEASE_CANDIDATE)?(_.+)?\z/

    case Regex.run(rx, bare) do
      [_ | groups] ->
        [major, letter, minor, patch, rc, topic] = pad(groups, 6)

        if topic == "",
          do: {:ok, String.to_integer(major), letter, to_int(minor), to_int(patch), rc != ""},
          else: :error

      _no_match ->
        :error
    end
  end

  defp to_int(""), do: 0
  defp to_int(s), do: String.to_integer(s)

  defp letter_rank(<<c>>) when c in ?A..?Z, do: c - ?A + 1

  defp pad(list, n), do: list ++ List.duplicate("", n - length(list))
end
