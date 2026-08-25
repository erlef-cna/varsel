# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.SemverVersion do
  @moduledoc """
  Parses and orders semver release versions — hex and the wider ecosystem — in
  the shape of `Varsel.Cases.Reachability.OTPVersion`.

  Ordering and pre-release precedence are delegated to Elixir's `Version`; a
  leading `v` is stripped first. A tag that is not valid semver (e.g. `nightly`,
  `v1.19-latest`) is not a release version — `parse/1` returns `:error`.
  """

  @enforce_keys [:version, :raw]
  defstruct [:version, :raw]

  @type t :: %__MODULE__{
          version: Version.t(),
          raw: String.t()
        }

  @doc "Parses a semver version string. `:error` for non-version tags."
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(version) when is_binary(version) do
    case Version.parse(String.replace_prefix(version, "v", "")) do
      {:ok, %Version{} = v} -> {:ok, %__MODULE__{version: v, raw: version}}
      :error -> :error
    end
  end

  @doc """
  Compares two semver versions (strings or parsed structs), delegating to
  `Version.compare/2` for correct semver precedence (incl. pre-release
  identifiers). Both must be valid releases — callers filter non-releases first.
  """
  @spec compare(String.t() | t(), String.t() | t()) :: :lt | :eq | :gt
  def compare(left, right), do: Version.compare(to_version(left), to_version(right))

  @doc "Whether the scheme orders every pair of versions. Semver does."
  @spec total_order?() :: boolean()
  def total_order?, do: true

  @doc "Whether `version` is valid semver (a real release)."
  @spec release?(String.t()) :: boolean()
  def release?(version), do: match?({:ok, _}, parse(version))

  @doc "Whether `version` is a pre-release."
  @spec prerelease?(String.t()) :: boolean()
  def prerelease?(version) do
    case parse(version) do
      {:ok, v} -> v.version.pre != []
      :error -> false
    end
  end

  ## ------------------------------------------------------------ internals

  defp to_version(%__MODULE__{version: v}), do: v

  defp to_version(string) when is_binary(string), do: Version.parse!(String.replace_prefix(string, "v", ""))
end
