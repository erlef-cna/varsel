# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.DerivationFreshness do
  @moduledoc """
  Shared predicates over an affected package's cached derivation, so the
  preview blockers (`Case.Calculations.Preview`) and the workspace section rail
  (`Readiness`) agree on when a package's derived version data is unusable.

  Derivation is refreshed explicitly (`refresh_derivation`), never eagerly, so
  the cache goes stale the moment a boundary fact, channel, or the package
  itself is edited after the last refresh. A stale or empty derivation renders
  as *no affected versions* — a silently-wrong record — so both callers must
  treat it as needing attention rather than trusting the empty ranges.

  The package must have `:channels` and `:version_events` loaded, with their
  `updated_at` timestamps (the preview calc and readiness both load the full
  attribute set).
  """

  alias Varsel.Cases.AffectedPackage

  @doc """
  Whether the package's `derivation_cache` predates the facts it derives from
  — a nil cache (never refreshed) counts as stale. Compares
  `derivation_cached_at` against the newest `updated_at` across the package and
  its channels and version events.
  """
  @spec stale?(AffectedPackage.t()) :: boolean()
  def stale?(%{derivation_cached_at: nil}), do: true

  def stale?(%{derivation_cached_at: cached_at} = package) do
    DateTime.before?(cached_at, newest_fact(package))
  end

  @doc """
  Whether a *fresh* derivation yields no affected versions on any channel,
  despite the package carrying an introduced boundary fact. This is the genuine
  empty-derivation case (as opposed to staleness): the facts are there and
  current, but resolution produced nothing renderable.

  Returns `false` when the cache is stale (staleness is reported separately, and
  an out-of-date cache says nothing reliable about the derived versions) or when
  there is no introduced boundary to derive from in the first place.
  """
  @spec missing_versions?(AffectedPackage.t()) :: boolean()
  def missing_versions?(package) do
    not stale?(package) and has_introduced_boundary?(package) and
      derived_versions(package.derivation_cache) == []
  end

  defp has_introduced_boundary?(%{version_events: events}) when is_list(events) do
    Enum.any?(events, &(&1.event == :introduced))
  end

  defp has_introduced_boundary?(_package), do: false

  # Every renderable range across the package's channels.
  defp derived_versions(nil), do: []

  defp derived_versions(cache) do
    cache
    |> Map.get("channels", %{})
    |> Map.values()
    |> Enum.flat_map(&(&1["versions"] || []))
  end

  defp newest_fact(package) do
    [package | package.channels ++ package.version_events]
    |> Enum.map(& &1.updated_at)
    |> Enum.reject(&is_nil/1)
    |> Enum.max(DateTime)
  end
end
