# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.OsvRecord.Changes.Sync do
  @moduledoc """
  Oban worker change: re-derives the OSV document from the parent CVE record
  and refreshes the enumerated hex.pm affected versions. Idempotent — the OSV
  `modified` timestamp only advances when the derived content actually changed.
  """

  use Ash.Resource.Change

  alias Varsel.CVE.OsvRecord

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    record = changeset.data
    cve_record = Varsel.CVE.get_cve_record!(record.cve_record_id, authorize?: false)
    now = DateTime.utc_now()

    case OsvRecord.derive(cve_record) do
      {:ok, _osv, content_hash}
      when content_hash == record.content_hash and is_nil(record.withdrawn_at) ->
        Ash.Changeset.force_change_attribute(changeset, :synced_at, now)

      {:ok, osv, content_hash} ->
        changeset
        |> Ash.Changeset.force_change_attribute(:synced_at, now)
        |> Ash.Changeset.force_change_attribute(:osv_json, OsvRecord.stamp_modified(osv, now))
        |> Ash.Changeset.force_change_attribute(:content_hash, content_hash)
        |> Ash.Changeset.force_change_attribute(:modified_at, now)
        |> Ash.Changeset.force_change_attribute(:withdrawn_at, nil)

      {:skip, _reason} when not is_nil(record.withdrawn_at) ->
        Ash.Changeset.force_change_attribute(changeset, :synced_at, now)

      {:skip, _reason} ->
        osv_json =
          record.osv_json
          |> Map.put("withdrawn", DateTime.to_iso8601(now))
          |> OsvRecord.stamp_modified(now)

        changeset
        |> Ash.Changeset.force_change_attribute(:synced_at, now)
        |> Ash.Changeset.force_change_attribute(:osv_json, osv_json)
        |> Ash.Changeset.force_change_attribute(:modified_at, now)
        |> Ash.Changeset.force_change_attribute(:withdrawn_at, now)

      # Transient state (the parent moved between the worker read and here,
      # e.g. :published -> :pending_update): leave the record untouched — it is
      # revisited once the parent settles.
      :defer ->
        changeset

      {:error, reason} ->
        Ash.Changeset.add_error(changeset, reason)
    end
  end
end
