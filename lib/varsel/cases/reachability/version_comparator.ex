# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.VersionComparator do
  @moduledoc """
  Dispatches version questions to the module for the ecosystem's versioning
  scheme, so `Varsel.Cases.Reachability` stays scheme-agnostic:

    * `:semver` — `Varsel.Cases.Reachability.SemverVersion` (hex and the wider
      ecosystem, over Elixir's `Version`).
    * `:otp` — `Varsel.Cases.Reachability.OTPVersion` (the numeric releases,
      17.0 and up).

  Both target modules expose the same API (`parse/1`, `compare/2`, `release?/1`,
  `prerelease?/1`); this module only picks between them.

  It answers for one value itself: `0`, the CVE record's "since the first
  version". That is a bound rather than a release, so no scheme parses it, and
  it orders below every version in any of them.

  `compare/2` is total, since a timeline has to be sorted. `implies?/3` is the
  partial question — whether one boundary already covers another — which OTP's
  branch versions answer with "neither".
  """

  alias Varsel.Cases.Reachability.OTPVersion
  alias Varsel.Cases.Reachability.SemverVersion

  @type kind :: :semver | :otp

  @zero "0"

  @doc "The bound naming the start of all history, which orders below every version."
  @spec zero() :: String.t()
  def zero, do: @zero

  @spec module(kind()) :: module()
  defp module(:semver), do: SemverVersion
  defp module(:otp), do: OTPVersion

  @doc "Parses `version` under `kind`. `:error` for non-release tags."
  @spec parse(kind(), String.t()) :: {:ok, struct()} | :error
  def parse(kind, version), do: module(kind).parse(version)

  @doc """
  Compares two versions under `kind` on one line: `:lt` | `:eq` | `:gt`.

  Total, so a timeline can be sorted and cut into ranges. OTP's scheme is only
  partially ordered; where it declines to order two versions this still picks
  one, consistently. `implies?/3` is the question that respects the gap.
  """
  @spec compare(kind(), String.t(), String.t()) :: :lt | :eq | :gt
  def compare(_kind, @zero, @zero), do: :eq
  def compare(_kind, @zero, _other), do: :lt
  def compare(_kind, _other, @zero), do: :gt
  def compare(:otp, a, b), do: OTPVersion.total_compare(a, b)
  def compare(kind, a, b), do: module(kind).compare(a, b)

  @doc """
  Whether `kind` orders every pair of versions.

  False for a scheme whose versions branch, where two releases can each carry
  changes the other lacks. A record over such a scheme cannot state an affected
  span as one `version → lessThan` range, since the range asserts an order
  between its bounds.

  True for a type this module does not order at all — dates, image tags, vendor
  strings. Nothing here compares their bounds, so nothing here can claim they
  branch.
  """
  @spec total_order?(atom()) :: boolean()
  def total_order?(:semver), do: SemverVersion.total_order?()
  def total_order?(:otp), do: OTPVersion.total_order?()
  def total_order?(_unordered_type), do: true

  @doc """
  Whether every version at or after `b` is also at or after `a` — that is,
  whether a boundary at `a` already covers one at `b`.

  False when the scheme puts the two on branches that never meet: OTP's
  `27.3.4.15` says nothing about `28.0`, so neither boundary implies the other
  and a record needs both.
  """
  @spec implies?(kind(), String.t(), String.t()) :: boolean()
  def implies?(_kind, @zero, _other), do: true
  def implies?(_kind, _other, @zero), do: false
  def implies?(:otp, a, b), do: OTPVersion.compare(a, b) in [:lt, :eq]
  def implies?(kind, a, b), do: module(kind).compare(a, b) in [:lt, :eq]

  @doc """
  Whether `version` bounds a range under `kind`: a real release, or the zero
  bound.
  """
  @spec release?(kind(), String.t()) :: boolean()
  def release?(_kind, @zero), do: true
  def release?(kind, version), do: module(kind).release?(version)

  @doc "Whether `version` is a pre-release under `kind`."
  @spec prerelease?(kind(), String.t()) :: boolean()
  def prerelease?(_kind, @zero), do: false
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
