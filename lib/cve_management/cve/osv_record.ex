# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.OsvRecord do
  @moduledoc """
  The OSV document derived from a published `CveRecord`.

  This resource owns the entire OSV lifecycle — the CVE side carries nothing
  but the `osv_record` relationship:

  - The scheduled `:create_missing` action finds published CVE records
    without an OSV record (a cheap SQL anti-join) and derives one for each
    convertible record. Records without an OSV representation (no hex/git
    affected entries) are skipped.

  - The `:sync` trigger re-derives each record on its own clock — when its
    parent's `cve_json` changed since the last sync (`synced_at <
    cve_record.date_updated`), when the last sync is older than 24 hours
    (refreshing the enumerated hex.pm versions), or when the parent was
    rejected. There is no bulk resync.

  - `CveManagement.CVE.OsvRecord.Notifier` (attached to `CveRecord`) enqueues
    both checks the moment a CVE record changes; the 15-minute schedulers are
    the safety net for changes that produce no notification (bulk imports,
    external MITRE edits).

  `modified_at` mirrors the document's `modified` timestamp and only
  advances when `content_hash` — the hash of the document without
  `modified` — changes, so upstream consumers (osv.dev) re-import exactly
  when something changed, including when a new hex.pm release lands inside
  an affected range.

  A record whose CVE is rejected or becomes non-convertible is withdrawn
  (`withdrawn_at` set, `withdrawn` added to the document) rather than
  deleted, telling OSV consumers to drop it. A withdrawn record is only
  revisited when its parent changes again — and is un-withdrawn if that
  change made it convertible again.
  """
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.CVE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban]

  import Ash.Expr

  alias CveManagement.CVE.CveRecord
  alias CveManagement.CVE.CveRecord.OkResult
  alias CveManagement.CVE.HexPm
  alias CveManagement.CVE.OsvConverter

  require Ash.Query

  postgres do
    table "osv_records"
    repo CveManagement.Repo

    references do
      reference :cve_record, on_delete: :delete
    end
  end

  oban do
    triggers do
      trigger :sync do
        action :sync

        # Per-record staleness check instead of a bulk resync. Only the
        # terminal :rejected state withdraws — transient states (e.g.
        # :pending_update while a push to MITRE is in flight) leave the OSV
        # record untouched. Withdrawn records are only revisited when their
        # parent changes again.
        where expr(
                (is_nil(withdrawn_at) and
                   ((cve_record.state == :published and
                       (synced_at < ago(24, :hour) or synced_at < cve_record.date_updated)) or
                      cve_record.state == :rejected)) or
                  (not is_nil(withdrawn_at) and cve_record.state == :published and
                     synced_at < cve_record.date_updated)
              )

        worker_module_name CveManagement.CVE.OsvRecord.SyncWorker
        scheduler_module_name CveManagement.CVE.OsvRecord.SyncScheduler
        queue :osv_sync
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end

    scheduled_actions do
      schedule :create_missing, "*/15 * * * *",
        action: :create_missing,
        worker_module_name: CveManagement.CVE.OsvRecord.CreateMissingWorker,
        queue: :osv_sync,
        max_attempts: 3
    end
  end

  actions do
    defaults [:read]

    read :list_feed do
      description "Lists all OSV records for the /osv/all.json feed."
      prepare build(sort: [osv_id: :asc])
    end

    read :get do
      description "Fetches a single OSV record by its OSV ID (EEF-CVE-...)."
      argument :osv_id, :string, allow_nil?: false
      get? true
      filter expr(osv_id == ^arg(:osv_id))
    end

    create :create do
      accept [:osv_id, :cve_record_id, :osv_json, :content_hash, :modified_at, :synced_at]

      # Concurrent runs racing the create_missing anti-join collapse into an
      # idempotent upsert instead of a unique violation.
      upsert? true
      upsert_identity :unique_cve_record
      upsert_fields [:osv_id, :osv_json, :content_hash, :modified_at, :synced_at]
    end

    action :create_missing, OkResult do
      description """
      Creates OSV records for published CVE records that do not have one yet.
      Published records without an OSV representation are skipped and checked
      again on the next run. Failures are isolated per record — the job only
      raises (for the Oban retry) after all records were attempted.
      """

      run fn _input, _context ->
        errors =
          CveRecord
          |> Ash.Query.filter(state == :published and not exists(osv_record, true))
          |> Ash.read!(authorize?: false)
          |> Enum.flat_map(fn cve_record ->
            case derive(cve_record) do
              {:ok, osv, content_hash} ->
                now = DateTime.utc_now()

                Ash.create!(
                  __MODULE__,
                  %{
                    osv_id: osv["id"],
                    cve_record_id: cve_record.id,
                    osv_json: stamp_modified(osv, now),
                    content_hash: content_hash,
                    modified_at: now,
                    synced_at: now
                  },
                  action: :create,
                  authorize?: false
                )

                []

              {:skip, _reason} ->
                []

              {:error, reason} ->
                [{get_in(cve_record.cve_json, ["cveMetadata", "cveId"]), reason}]
            end
          end)

        if errors == [] do
          {:ok, :ok}
        else
          raise "Failed to create OSV records: #{inspect(errors)}"
        end
      end
    end

    update :sync do
      description """
      Oban worker action: re-derives the OSV document from the parent CVE
      record and refreshes the enumerated hex.pm affected versions.
      Idempotent — the OSV modified timestamp only advances when the derived
      content actually changed.
      """

      accept []
      require_atomic? false

      change fn changeset, _context ->
        record = changeset.data
        cve_record = Ash.get!(CveRecord, record.cve_record_id, authorize?: false)
        now = DateTime.utc_now()

        case derive(cve_record) do
          {:ok, _osv, content_hash}
          when content_hash == record.content_hash and is_nil(record.withdrawn_at) ->
            Ash.Changeset.force_change_attribute(changeset, :synced_at, now)

          {:ok, osv, content_hash} ->
            changeset
            |> Ash.Changeset.force_change_attribute(:synced_at, now)
            |> Ash.Changeset.force_change_attribute(:osv_json, stamp_modified(osv, now))
            |> Ash.Changeset.force_change_attribute(:content_hash, content_hash)
            |> Ash.Changeset.force_change_attribute(:modified_at, now)
            |> Ash.Changeset.force_change_attribute(:withdrawn_at, nil)

          {:skip, _reason} when not is_nil(record.withdrawn_at) ->
            Ash.Changeset.force_change_attribute(changeset, :synced_at, now)

          {:skip, _reason} ->
            osv_json =
              record.osv_json
              |> Map.put("withdrawn", DateTime.to_iso8601(now))
              |> stamp_modified(now)

            changeset
            |> Ash.Changeset.force_change_attribute(:synced_at, now)
            |> Ash.Changeset.force_change_attribute(:osv_json, osv_json)
            |> Ash.Changeset.force_change_attribute(:modified_at, now)
            |> Ash.Changeset.force_change_attribute(:withdrawn_at, now)

          # Transient state (the parent moved between the worker read and
          # here, e.g. :published -> :pending_update): leave the record
          # untouched — it is revisited once the parent settles.
          :defer ->
            changeset

          {:error, reason} ->
            Ash.Changeset.add_error(changeset, reason)
        end
      end
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    # OSV records are derived from published CVE data and fully public.
    policy action_type(:read) do
      authorize_if always()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :osv_id, :string do
      description "The OSV identifier, e.g. EEF-CVE-2025-12345."
      allow_nil? false
      public? true
    end

    attribute :osv_json, :map do
      description "The full OSV document as served to consumers."
      allow_nil? false
      public? true
    end

    attribute :content_hash, :string do
      description "Hash of the OSV document without its modified timestamp."
      allow_nil? false
    end

    attribute :modified_at, :utc_datetime_usec do
      description "Mirrors the document's modified timestamp; advances only on content changes."
      allow_nil? false
      public? true
    end

    attribute :synced_at, :utc_datetime_usec do
      description "When the document was last checked against the parent CVE record and hex.pm."
      allow_nil? false
    end

    attribute :withdrawn_at, :utc_datetime_usec do
      description "Set when the underlying CVE was rejected or stopped being convertible."
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :cve_record, CveRecord do
      allow_nil? false
    end
  end

  identities do
    identity :unique_osv_id, [:osv_id]
    identity :unique_cve_record, [:cve_record_id]
  end

  # Derives the full OSV document (with enumerated hex.pm versions) and its
  # content hash from a CVE record.
  # Only the terminal :rejected state skips (and thereby withdraws); other
  # non-published states defer until the parent settles.
  defp derive(%CveRecord{state: :rejected}), do: {:skip, "CVE record is rejected"}

  defp derive(%CveRecord{state: :published, cve_json: cve_json}) do
    with {:ok, osv} <- OsvConverter.convert(cve_json),
         {:ok, osv} <- OsvConverter.enumerate_affected_versions(osv, &HexPm.package_versions/1) do
      {:ok, osv, OsvConverter.content_hash(osv)}
    end
  end

  defp derive(%CveRecord{}), do: :defer

  defp stamp_modified(osv, %DateTime{} = at), do: Map.put(osv, "modified", DateTime.to_iso8601(at))
end
