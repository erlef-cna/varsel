# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.VersionComparator do
  @moduledoc """
  Dispatches version questions to the module for the ecosystem's versioning
  scheme, so `Varsel.Cases.Reachability` stays scheme-agnostic:

    * `:semver` — `Varsel.Cases.Reachability.SemverVersion` (hex and the wider
      ecosystem, over Elixir's `Version`).
    * `:otp` — `Varsel.Cases.Reachability.OTPVersion` (modern numeric + legacy
      R-series).

  Both target modules expose the same API (`parse/1`, `compare/2`, `release?/1`,
  `prerelease?/1`); this module only picks between them. It carries no parsing or
  ordering logic of its own.
  """

  alias Varsel.Cases.Reachability.OTPVersion
  alias Varsel.Cases.Reachability.SemverVersion

  @type kind :: :semver | :otp

  @spec module(kind()) :: module()
  defp module(:semver), do: SemverVersion
  defp module(:otp), do: OTPVersion

  @doc "Parses `version` under `kind`. `:error` for non-release tags."
  @spec parse(kind(), String.t()) :: {:ok, struct()} | :error
  def parse(kind, version), do: module(kind).parse(version)

  @doc "Compares two versions under `kind`: `:lt` | `:eq` | `:gt`."
  @spec compare(kind(), String.t(), String.t()) :: :lt | :eq | :gt
  def compare(kind, a, b), do: module(kind).compare(a, b)

  @doc "Whether `version` names a real release under `kind`."
  @spec release?(kind(), String.t()) :: boolean()
  def release?(kind, version), do: module(kind).release?(version)

  @doc "Whether `version` is a pre-release under `kind`."
  @spec prerelease?(kind(), String.t()) :: boolean()
  def prerelease?(kind, version), do: module(kind).prerelease?(version)

  @doc """
  Sorts `items` ascending by version under `kind`, reading each item's version
  string with `version_fun`.
  """
  @spec sort(kind(), [item], (item -> String.t())) :: [item] when item: var
  def sort(kind, items, version_fun) do
    Enum.sort_by(items, version_fun, &(compare(kind, &1, &2) != :gt))
  end
end
