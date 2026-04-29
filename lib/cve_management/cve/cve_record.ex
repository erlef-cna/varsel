# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.CveRecord.OkResult do
  @moduledoc false
  use Ash.Type.Enum, values: [:ok]
end

defmodule CveManagement.CVE.CveRecord do
  @moduledoc """
  Represents a CVE record and its lifecycle from initial submission through publication.

  ## State Machine

  ```mermaid
  stateDiagram-v2
    [*] --> publishing
    [*] --> published : import
    publishing --> published : publish (Oban)
    published --> pending_update : update (user)
    pending_update --> published : push_update (Oban)
  ```

  ## Actions

  - `:create` — Creates a new record in the `:publishing` state and immediately enqueues a
    publish job. The Oban worker calls the MITRE API to submit the CNA container, then
    transitions the record to `:published`.

  - `:update` — Transitions a `:published` record to `:pending_update` with new `cve_json`
    and immediately enqueues a push_update job. The Oban worker pushes the changes to MITRE.

  - `:import` — Upserts a record from MITRE directly into the `:published` state. Used by
    the scheduled `import_from_mitre` action. No-op if the CVE ID already exists locally.

  - `:import_from_mitre` (generic) — Scheduled daily via Oban. Fetches all published CVE IDs
    owned by the org from MITRE and imports any that do not exist locally.

  - `:sync_from_mitre` (update) — Scheduled daily via Oban. For each `:published` record,
    fetches the current state from MITRE and updates `cve_json` if MITRE has a newer version.
  """
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.CVE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshStateMachine, AshOban]

  alias CveManagement.CVE.CveReservation
  alias CveManagement.CVE.MitreCveApi

  require Ash.Query

  postgres do
    table "cve_records"
    repo CveManagement.Repo

    calculations_to_sql cve_id: "cve_json->'cveMetadata'->>'cveId'",
                        title: "cve_json->'containers'->'cna'->>'title'"
  end

  state_machine do
    initial_states [:publishing, :published]
    default_initial_state :publishing

    transitions do
      transition :publish, from: :publishing, to: :published
      transition :update, from: :published, to: :pending_update
      transition :update, from: :pending_update, to: :pending_update
      transition :push_update, from: :pending_update, to: :published
    end
  end

  oban do
    triggers do
      trigger :publish do
        action :publish
        where expr(state == :publishing)
        worker_module_name CveManagement.CVE.CveRecord.PublishWorker
        scheduler_module_name CveManagement.CVE.CveRecord.PublishScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end

      trigger :push_update do
        action :push_update
        where expr(state == :pending_update)
        worker_module_name CveManagement.CVE.CveRecord.PushUpdateWorker
        scheduler_module_name CveManagement.CVE.CveRecord.PushUpdateScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end

      trigger :sync_from_mitre do
        action :sync_from_mitre
        where expr(state == :published)
        worker_module_name CveManagement.CVE.CveRecord.SyncFromMitreWorker
        scheduler_module_name CveManagement.CVE.CveRecord.SyncFromMitreScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "0 2 * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end

    scheduled_actions do
      schedule :import_from_mitre, "0 2 * * *",
        action: :import_from_mitre,
        worker_module_name: CveManagement.CVE.CveRecord.ImportFromMitreWorker,
        queue: :cve_publishing,
        max_attempts: 3
    end
  end

  actions do
    defaults [:read]

    read :list_published do
      prepare build(
                load: [:cve_id, :title, :date_published, :date_updated],
                sort: [date_published: :desc]
              )
    end

    read :get_published do
      argument :cve_id, :string, allow_nil?: false
      get? true
      filter expr(cve_id == ^arg(:cve_id))
    end

    create :create do
      primary? true
      accept [:cve_json, :case_id]
      change run_oban_trigger(:publish)
    end

    create :import do
      description "Imports a CVE record from MITRE as already-published. No-op if it already exists."
      accept [:cve_json]
      upsert? true
      upsert_identity :unique_cve_id
      upsert_fields [:state]

      change set_attribute(:state, :published)
    end

    action :import_from_mitre, CveManagement.CVE.CveRecord.OkResult do
      description "Fetches all CVE IDs from MITRE and imports any that do not exist locally."

      run fn _input, _context ->
        MitreCveApi.stream_ids()
        |> Enum.map(fn cve_id ->
          {:ok, cve_json} = MitreCveApi.get(cve_id)
          %{cve_json: cve_json}
        end)
        |> Enum.chunk_every(100)
        |> Enum.each(fn chunk ->
          Ash.bulk_create!(chunk, __MODULE__, :import, authorize?: false)
        end)

        {:ok, :ok}
      end
    end

    update :update do
      accept [:cve_json]
      change transition_state(:pending_update)
      change run_oban_trigger(:push_update)
    end

    update :push_update do
      accept []
      require_atomic? false

      change fn changeset, _context ->
        record = changeset.data

        if record.state == :published do
          # Already pushed — idempotent no-op (concurrent job succeeded first)
          changeset
        else
          cve_id = get_in(record.cve_json, ["cveMetadata", "cveId"])
          cna_container = record.cve_json |> Map.get("containers", %{}) |> Map.get("cna", %{})

          with {:ok, _} <- MitreCveApi.update_cna(cve_id, cna_container),
               {:ok, full_record} <- MitreCveApi.get(cve_id) do
            changeset
            |> Ash.Changeset.force_change_attribute(:cve_json, full_record)
            |> Ash.Changeset.force_change_attribute(:last_synced_at, DateTime.utc_now())
            |> AshStateMachine.transition_state(:published)
          else
            {:error, reason} -> Ash.Changeset.add_error(changeset, reason)
          end
        end
      end
    end

    update :sync_from_mitre do
      accept []
      require_atomic? false

      change fn changeset, _context ->
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
              Ash.Changeset.force_change_attribute(changeset, :last_synced_at, DateTime.utc_now())
            end

          {:error, reason} ->
            Ash.Changeset.add_error(changeset, reason)
        end
      end
    end

    update :publish do
      accept []
      require_atomic? false

      change fn changeset, _context ->
        record = changeset.data

        if record.state == :published do
          # Already published — idempotent no-op (concurrent job succeeded first)
          changeset
        else
          cve_id = get_in(record.cve_json, ["cveMetadata", "cveId"])
          cna_container = record.cve_json |> Map.get("containers", %{}) |> Map.get("cna", %{})

          with {:ok, _} <- MitreCveApi.publish(cve_id, cna_container),
               {:ok, full_record} <- MitreCveApi.get(cve_id) do
            changeset
            |> Ash.Changeset.force_change_attribute(:cve_json, full_record)
            |> AshStateMachine.transition_state(:published)
          else
            {:error, reason} -> Ash.Changeset.add_error(changeset, reason)
          end
        end
      end

      change after_action(fn changeset, record, _context ->
               destroy_reservation(record)
               {:ok, record}
             end)
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if expr(state == :published)
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :cve_json, :map do
      allow_nil? false
      public? true
    end

    attribute :last_synced_at, :utc_datetime do
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, CveManagement.Cases.Case do
      public? true
      allow_nil? true
    end
  end

  calculations do
    calculate :cve_id, :string, expr(fragment("?->'cveMetadata'->>'cveId'", cve_json)) do
      public? true
    end

    calculate :title, :string, expr(fragment("?->'containers'->'cna'->>'title'", cve_json)) do
      public? true
    end

    calculate :date_published,
              :utc_datetime,
              expr(
                fragment(
                  "(?->'cveMetadata'->>'datePublished')::timestamptz",
                  cve_json
                )
              ) do
      public? true
    end

    calculate :date_updated,
              :utc_datetime,
              expr(
                fragment(
                  "(?->'cveMetadata'->>'dateUpdated')::timestamptz",
                  cve_json
                )
              ) do
      public? true
    end
  end

  identities do
    identity :unique_cve_id, [:cve_id]
  end

  defp destroy_reservation(record) do
    cve_id = get_in(record.cve_json, ["cveMetadata", "cveId"])

    CveReservation
    |> Ash.Query.filter(cve_id: cve_id)
    |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false, return_errors?: true)

    :ok
  end

  defp parse_datetime(nil), do: nil

  defp parse_datetime(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
end
