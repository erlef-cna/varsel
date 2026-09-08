# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Ranges do
  @moduledoc """
  GitHub's version-range language, as `vulnerable_version_range` and
  `patched_versions` speak it: one span per entry, such as `>= 1.0.0, < 1.2.3`
  or `< 1.2.3`, and a comma-separated list of fixed versions.

  `format/2` writes a span. `Varsel.Cases.Derivation.Emit` decides which spans
  a channel states. `normalize/1` and `split_versions/1` read what GitHub
  sends back, so the two sides compare as strings.
  """

  alias Varsel.Cases.Reachability.VersionComparator

  @doc """
  The range for a span from `from` up to but excluding `until`. Either side
  is nil when open. A span open below is written without a lower bound, as
  GitHub does. One open on both sides covers every version.
  """
  @spec format(String.t() | nil, String.t() | nil) :: String.t()
  def format(from, until) do
    case {lower(from), until} do
      {nil, nil} -> ">= 0"
      {nil, until} -> "< #{until}"
      {from, nil} -> ">= #{from}"
      {from, until} -> ">= #{from}, < #{until}"
    end
  end

  defp lower(from) do
    if from in [nil, VersionComparator.zero()], do: nil, else: from
  end

  @doc """
  A range string with GitHub's spacing (`>= 1.0, < 2.0`), so two spellings of
  one range compare equal. nil stays nil, and so does a blank.
  """
  @spec normalize(String.t() | nil) :: String.t() | nil
  def normalize(nil), do: nil

  def normalize(range) when is_binary(range) do
    range
    |> String.split(",", trim: true)
    |> Enum.map(&normalize_constraint/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join(", ")
    |> case do
      "" -> nil
      normalized -> normalized
    end
  end

  @doc "A comma-separated `patched_versions` value as a list, trimmed and in order."
  @spec split_versions(String.t() | nil) :: [String.t()]
  def split_versions(nil), do: []

  def split_versions(versions) when is_binary(versions) do
    versions
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp normalize_constraint(constraint) do
    case Regex.run(~r/\A\s*(>=|<=|>|<|=)?\s*(\S+)\s*\z/, constraint) do
      [_whole, "", version] -> "= #{version}"
      [_whole, operator, version] -> "#{operator} #{version}"
      nil -> String.trim(constraint)
    end
  end
end
