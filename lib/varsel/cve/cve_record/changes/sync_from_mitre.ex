# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Changes.SyncFromMitre do
  @moduledoc """
  Pulls the latest record from MITRE and adopts it only when its `dateUpdated`
  is newer than the local copy. When nothing meaningful changed, only
  `last_synced_at` is bumped and the paper-trail version is suppressed so
  bookkeeping-only syncs don't clutter the audit history.
  """

  use Ash.Resource.Change

  alias Varsel.CVE.MitreCveApi

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    record = changeset.data
    cve_id = get_in(record.cve_json, ["cveMetadata", "cveId"])

    case MitreCveApi.get(cve_id) do
      {:ok, remote_record} ->
        remote_updated =
          remote_record |> get_in(["cveMetadata", "dateUpdated"]) |> parse_datetime()

        local_updated =
          record.cve_json |> get_in(["cveMetadata", "dateUpdated"]) |> parse_datetime()

        if remote_updated != nil and
             (local_updated == nil or DateTime.after?(remote_updated, local_updated)) do
          changeset
          |> Ash.Changeset.force_change_attribute(:cve_json, remote_record)
          |> Ash.Changeset.force_change_attribute(:last_synced_at, DateTime.utc_now())
        else
          changeset
          |> Ash.Changeset.force_change_attribute(:last_synced_at, DateTime.utc_now())
          |> Ash.Changeset.set_context(%{ash_paper_trail_disabled?: true})
        end

      {:error, reason} ->
        Ash.Changeset.add_error(changeset, reason)
    end
  end

  defp parse_datetime(nil), do: nil

  defp parse_datetime(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
end
