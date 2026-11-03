# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Changes.SyncUpstream do
  @moduledoc """
  Oban worker change: refreshes an upstream CVE from MITRE.

  While the ID is reserved, MITRE has no record to fetch, so the change polls
  the ID object until it reads PUBLISHED or REJECTED. After that it adopts
  MITRE's record and keeps this CNA's ADP container in it. A sync that
  changes nothing bumps `last_synced_at` without a paper-trail version.
  """

  use Ash.Resource.Change

  alias Varsel.CVE.MitreCveApi
  alias Varsel.CVE.OwnContainer

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    record = changeset.data
    now = DateTime.utc_now()
    changeset = Ash.Changeset.force_change_attribute(changeset, :last_synced_at, now)

    case sync(record) do
      :unchanged ->
        Ash.Changeset.set_context(changeset, %{ash_paper_trail_disabled?: true})

      {:updated, cve_json} ->
        Ash.Changeset.force_change_attribute(changeset, :cve_json, cve_json)

      {:rejected, cve_json} ->
        changeset
        |> Ash.Changeset.force_change_attributes(
          cve_json: cve_json || record.cve_json,
          rejected_at: now,
          rejection_reason: "Rejected upstream at MITRE"
        )
        |> AshStateMachine.transition_state(:rejected)

      {:error, reason} ->
        Ash.Changeset.add_error(changeset, reason)
    end
  end

  defp sync(%{cve_json: nil, reservation_json: %{"cve_id" => cve_id}}) do
    case MitreCveApi.get_id(cve_id) do
      {:ok, %{"state" => "RESERVED"}} ->
        :unchanged

      {:ok, %{"state" => "REJECTED"}} ->
        {:rejected, nil}

      {:ok, %{"state" => "PUBLISHED"}} ->
        fetch(cve_id, &{:updated, &1})

      {:ok, %{"state" => state}} ->
        {:error, "#{cve_id} is in the unexpected MITRE state #{inspect(state)}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp sync(%{cve_json: %{"cveMetadata" => %{"cveId" => cve_id}} = local}) do
    fetch(cve_id, fn remote ->
      case keep_enrichment(remote, local) do
        %{"cveMetadata" => %{"state" => "REJECTED"}} = merged -> {:rejected, merged}
        ^local -> :unchanged
        merged -> {:updated, merged}
      end
    end)
  end

  defp fetch(cve_id, fun) do
    case MitreCveApi.get(cve_id) do
      {:ok, remote} -> fun.(remote)
      {:error, reason} -> {:error, reason}
    end
  end

  # MITRE does not hold this CNA's ADP container yet, so the local one
  # replaces whatever MITRE returns for this CNA. The record changed when
  # either side did, as it would at MITRE, so dateUpdated is the later one.
  defp keep_enrichment(remote, local) do
    case OwnContainer.get(local) do
      nil ->
        remote

      enrichment ->
        remote
        |> OwnContainer.put(enrichment)
        |> put_in(["cveMetadata", "dateUpdated"], later_date_updated(remote, local))
    end
  end

  defp later_date_updated(remote, local) do
    remote_date = get_in(remote, ["cveMetadata", "dateUpdated"])
    local_date = get_in(local, ["cveMetadata", "dateUpdated"])

    case {date_time(remote_date), date_time(local_date)} do
      {%DateTime{} = remote_at, %DateTime{} = local_at} ->
        if DateTime.after?(local_at, remote_at), do: local_date, else: remote_date

      {nil, _local_at} ->
        local_date

      {_remote_at, nil} ->
        remote_date
    end
  end

  defp date_time(date) when is_binary(date) do
    case DateTime.from_iso8601(date) do
      {:ok, at, _offset} -> at
      _invalid -> nil
    end
  end

  defp date_time(_missing), do: nil
end
