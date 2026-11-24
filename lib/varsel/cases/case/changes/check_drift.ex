# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.CheckDrift do
  @moduledoc """
  Renders a published case the way a publish would, and records whether that
  render differs from the CVE and OSV records that are published. A result
  other than in sync after an in-sync or a first check emits
  `:record_drifted`.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Case.Calculations.Preview.Diff
  alias Varsel.Cases.Signals

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    changeset
    |> Ash.Changeset.before_transaction(&check(&1, context))
    |> Ash.Changeset.after_action(&announce/2)
  end

  defp announce(%{data: %{record_drift: previous}} = changeset, %{record_drift: current} = record)
       when previous in [nil, :in_sync] and current not in [nil, :in_sync] do
    with :ok <- Ash.Signals.emit(changeset, Signals, :record_drifted, %{case_id: record.id}),
         do: {:ok, record}
  end

  defp announce(_changeset, record), do: {:ok, record}

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
    if Diff.published_changed?(case_record), do: :drifted, else: :in_sync
  end
end
