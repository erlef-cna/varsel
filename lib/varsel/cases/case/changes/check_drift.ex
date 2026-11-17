# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.CheckDrift do
  @moduledoc """
  Renders a published case the way a publish would, and records whether that
  render differs from the CVE and OSV records that are published.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Case.Calculations.Preview.Diff
  alias Varsel.CVE.OwnContainer

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_transaction(changeset, &check(&1, context))
  end

  defp check(changeset, context) do
    opts = Ash.Context.to_opts(context)

    drift =
      with {:ok, refreshed} <-
             Varsel.Cases.refresh_case_derivation(changeset.data, %{refresh: true}, opts),
           {:ok, loaded} <-
             Ash.load(
               refreshed,
               [:preview, :validation, :published_container, :published_osv],
               opts
             ) do
        verdict(loaded)
      else
        {:error, _error} -> :failed
      end

    changeset
    |> Ash.Changeset.force_change_attribute(:record_drift, drift)
    |> Ash.Changeset.force_change_attribute(:drift_checked_at, DateTime.utc_now())
  end

  defp verdict(%{preview: %{blockers: [_ | _]}}), do: :blocked
  defp verdict(%{validation: %{valid: false}}), do: :blocked

  defp verdict(case_record) do
    cve_changed? =
      Diff.changed?(
        Diff.lines(
          case_record.published_container || %{},
          OwnContainer.get(case_record.preview.cve_record)
        )
      )

    osv_changed? =
      Diff.changed?(Diff.lines(case_record.published_osv || %{}, case_record.preview.osv_record || %{}))

    if cve_changed? or osv_changed?, do: :drifted, else: :in_sync
  end
end
