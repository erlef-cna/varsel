# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveView.AffectedChecker do
  @moduledoc """
  Version parsing and ordering for the presentation layer — sorting a range's
  `changes[]` boundaries into version order so the Affected card can print them
  low to high.

  Deciding whether a version is affected is NOT done here: that is
  `Varsel.CVE.VersionResolution`, which implements the resolution algorithm the
  CVE Record Format specifies. This module only orders what the page displays.
  """

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

  def parse(_version, _type), do: :error

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
end
