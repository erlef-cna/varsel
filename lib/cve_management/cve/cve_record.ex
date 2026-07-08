# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.CveRecord.OkResult do
  @moduledoc false
  use Ash.Type.Enum, values: [:ok]
end

defmodule CveManagement.CVE.CveRecord do
  @moduledoc """
  Represents a single CVE ID through its entire lifecycle — from reservation in the
  MITRE pool, through drafting and publication, to eventual update or rejection.

  A CVE ID is a MITRE-owned resource that moves through one continuous lifecycle.
  Earlier states carry only `reservation_json` (the raw MITRE reservation object);
  once published the row also carries `cve_json` (the full MITRE record with
  `cveMetadata` and `containers`). Both blobs live side by side on the same row.

  ## State Machine

  ```mermaid
  stateDiagram-v2
    [*] --> reserved : reserve (pool top-up)
    [*] --> published : import
    reserved --> draft : assign
    reserved --> rejected : reject (stale / external)
    draft --> publishing : request_publish (user)
    draft --> rejected : reject
    publishing --> published : publish (Oban)
    published --> pending_update : update (user)
    published --> rejected : reject
    pending_update --> published : push_update (Oban)
  ```

  | State | Meaning |
  | --- | --- |
  | `reserved` | Reserved from MITRE, open in the pool |
  | `draft` | Taken out of the pool for drafting, not yet published |
  | `publishing` | Publish job enqueued; pushing the CNA container to MITRE |
  | `published` | MITRE accepted the record; `cve_json` set |
  | `pending_update` | Local edits to `cve_json` awaiting push to MITRE |
  | `rejected` | Terminal — rejected at MITRE; the ID is burned and never reused |

  At MITRE both `reserved` and `draft` are simply `RESERVED`; the distinction is
  purely local. `draft` is one-way — an assigned CVE is never returned to the open
  pool; it can only be published or rejected.

  ## Actions

  - `:reserve` (create) — Inserts/upserts a pool entry in the `:reserved` state from a
    raw MITRE reservation object.

  - `:import` — Upserts a record directly into the `:published` state from a full MITRE
    record. Used by the scheduled `import_from_mitre` action.

  - `:assign` (update) — Transitions a `:reserved` record to `:draft`, taking it out of
    the open pool.

  - `:request_publish` (update) — Accepts the `cve_json` for a `:draft` record, transitions
    it to `:publishing`, and enqueues a publish job. The Oban `:publish` worker then calls
    the MITRE API to submit the CNA container and transitions the record to `:published`.

  - `:update` (update) — Transitions a `:published` record to `:pending_update` with new
    `cve_json` and enqueues a push_update job.

  - `:reject` (update) — Transitions a `:reserved`, `:draft`, or `:published` record to
    the terminal `:rejected` state, rejecting the ID at MITRE and recording the reason.

  - `:import_from_mitre` / `:sync_from_mitre` — Scheduled daily; keep published records
    in sync with MITRE.

  - `:top_up_pool` / `:sync_reserved_from_mitre` / `:run_reject_stale` — Scheduled pool
    maintenance (see ADR-014).
  """
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.CVE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshStateMachine, AshOban, AshPaperTrail.Resource]

  import Ash.Expr

  alias CveManagement.CVE.CveRecord.OkResult
  alias CveManagement.CVE.CveRecord.Validations.ValidCveRecord
  alias CveManagement.CVE.MitreCveApi

  require Ash.Query

  postgres do
    table "cve_records"
    repo CveManagement.Repo

    calculations_to_sql cve_id: "coalesce(cve_json->'cveMetadata'->>'cveId', reservation_json->>'cve_id')",
                        title: "cve_json->'containers'->'cna'->>'title'",
                        reserved_at: "(reservation_json->>'reserved')::timestamptz",
                        year: "(reservation_json->>'cve_year')::integer",
                        search_vector: "search_vector"

    custom_statements do
      statement :cve_record_search_vector_fn do
        up """
        CREATE FUNCTION cve_record_search_vector(cve_json jsonb)
        RETURNS tsvector
        LANGUAGE sql
        IMMUTABLE PARALLEL SAFE
        AS $$
          SELECT
            setweight(to_tsvector('english', coalesce(cve_json->'cveMetadata'->>'cveId', '')), 'A') ||
            setweight(to_tsvector('english', coalesce(cve_json->'containers'->'cna'->>'title', '')), 'A') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(d->>'value', ' ')
               FROM jsonb_array_elements(coalesce(cve_json->'containers'->'cna'->'descriptions', '[]'::jsonb)) AS d),
              ''
            )), 'B') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(
                 coalesce(a->>'packageName', '') || ' ' ||
                 coalesce(a->>'product', '') || ' ' ||
                 coalesce(a->>'vendor', ''),
                 ' ')
               FROM jsonb_array_elements(coalesce(cve_json->'containers'->'cna'->'affected', '[]'::jsonb)) AS a),
              ''
            )), 'B') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(w->>'value', ' ')
               FROM jsonb_array_elements(coalesce(cve_json->'containers'->'cna'->'workarounds', '[]'::jsonb)) AS w),
              ''
            )), 'C') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(c->>'value', ' ')
               FROM jsonb_array_elements(coalesce(cve_json->'containers'->'cna'->'configurations', '[]'::jsonb)) AS c),
              ''
            )), 'C') ||
            setweight(to_tsvector('simple', regexp_replace(cve_json::text, '[^a-zA-Z0-9\s]', ' ', 'g')), 'D')
        $$
        """

        down "DROP FUNCTION IF EXISTS cve_record_search_vector(jsonb)"
      end

      statement :add_search_vector do
        up "ALTER TABLE cve_records ADD COLUMN search_vector tsvector GENERATED ALWAYS AS (cve_record_search_vector(coalesce(cve_json, '{}'::jsonb))) STORED"
        down "ALTER TABLE cve_records DROP COLUMN IF EXISTS search_vector"
      end

      statement :add_search_vector_gin_index do
        up "CREATE INDEX cve_records_search_vector_gin ON cve_records USING GIN (search_vector)"
        down "DROP INDEX IF EXISTS cve_records_search_vector_gin"
      end

      statement :add_affected_gin_index do
        up "CREATE INDEX cve_records_affected_gin ON cve_records USING GIN ((cve_json->'containers'->'cna'->'affected'))"
        down "DROP INDEX IF EXISTS cve_records_affected_gin"
      end
    end
  end

  state_machine do
    initial_states [:reserved, :published]
    default_initial_state :reserved

    transitions do
      transition :assign, from: :reserved, to: :draft
      transition :request_publish, from: :draft, to: :publishing
      transition :publish, from: :publishing, to: :published
      transition :update, from: :published, to: :pending_update
      transition :update, from: :pending_update, to: :pending_update
      transition :push_update, from: :pending_update, to: :published
      transition :reject, from: [:reserved, :draft, :published], to: :rejected
      transition :mark_rejected, from: [:reserved, :draft, :published], to: :rejected
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

      # skip_on_empty prevents the scheduled run from reserving IDs before the
      # first MITRE sync on a fresh database — the pool must be bootstrapped by
      # triggering :top_up_pool manually once (see the action's description).
      schedule :top_up_pool, "*/15 * * * *",
        action: :top_up_pool,
        action_input: %{skip_on_empty: true},
        worker_module_name: CveManagement.CVE.CveRecord.TopUpPoolWorker,
        queue: :cve_pool,
        max_attempts: 3

      schedule :sync_reserved_from_mitre, "0 3 * * *",
        action: :sync_reserved_from_mitre,
        worker_module_name: CveManagement.CVE.CveRecord.SyncReservedFromMitreWorker,
        queue: :cve_pool,
        max_attempts: 3

      schedule :reject_stale, "0 4 1 2 *",
        action: :run_reject_stale,
        worker_module_name: CveManagement.CVE.CveRecord.RejectStaleWorker,
        queue: :cve_pool,
        max_attempts: 3
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    attributes_as_attributes [:state]
    ignore_attributes [:last_synced_at, :inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, CveManagement.Accounts.User, domain: CveManagement.Accounts
  end

  actions do
    defaults [:read]

    read :list_published do
      prepare build(
                load: [:cve_id, :title, :date_published, :date_updated],
                sort: [date_published: :desc]
              )

      filter expr(state == :published)
    end

    read :get_published do
      argument :cve_id, :string, allow_nil?: false
      get? true
      filter expr(cve_id == ^arg(:cve_id) and state == :published)
    end

    read :search do
      description "Full-text search over CVE ID, title, descriptions, affected packages, workarounds, and configurations."
      argument :query, :string, allow_nil?: false

      prepare build(load: [:cve_id, :title, :date_published, :date_updated, :purls])
      filter expr(matches_query(query: ^arg(:query)) and state == :published)
    end

    read :list_by_purl do
      description "Lists published CVE records that affect a given package URL (PURL)."
      argument :purl, :string, allow_nil?: false

      prepare build(load: [:cve_id, :title, :date_published, :date_updated, :purls])

      filter expr(
               fragment(
                 "cve_json->'containers'->'cna'->'affected' @> jsonb_build_array(jsonb_build_object('packageURL', ?::text))",
                 ^arg(:purl)
               ) and state == :published
             )
    end

    read :available do
      description "Returns open (unassigned) reservations in the pool for a given year."

      argument :year, :integer, allow_nil?: false

      filter expr(state == :reserved and year == ^arg(:year))
    end

    create :reserve do
      description "Creates a pool reservation from a raw MITRE API reservation object."
      accept [:reservation_json]

      upsert? true
      upsert_identity :unique_cve_id
      upsert_fields [:reservation_json]

      change set_attribute(:state, :reserved)
    end

    create :import do
      description """
      Imports a CVE record from MITRE as already-published. Upserting an existing row
      (e.g. a local reservation published externally) fills cve_json and marks it published.
      """

      accept [:cve_json]
      upsert? true
      upsert_identity :unique_cve_id
      upsert_fields [:state, :cve_json]

      change set_attribute(:state, :published)
    end

    action :import_from_mitre, OkResult do
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

    update :assign do
      description "Takes a reserved CVE ID out of the open pool, moving it into the draft state."
      accept []
      change transition_state(:draft)
    end

    update :update do
      accept [:cve_json]
      require_atomic? false
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
              # Only bookkeeping changes — not worth an audit version
              changeset
              |> Ash.Changeset.force_change_attribute(:last_synced_at, DateTime.utc_now())
              |> Ash.Changeset.set_context(%{ash_paper_trail_disabled?: true})
            end

          {:error, reason} ->
            Ash.Changeset.add_error(changeset, reason)
        end
      end
    end

    update :request_publish do
      description """
      User-facing publish request. Accepts the CNA/ADP container JSON for a drafted
      CVE, transitions :draft -> :publishing, and enqueues the publish job. The Oban
      worker (:publish action) performs the remote MITRE call.
      """

      accept [:cve_json]
      require_atomic? false
      change transition_state(:publishing)
      change run_oban_trigger(:publish)
    end

    update :publish do
      description "Oban worker action: pushes the CNA container to MITRE and marks the record published."
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
    end

    update :reject do
      description """
      Rejects this CVE ID at MITRE and moves the row to the terminal :rejected state.
      Valid from :reserved, :draft, or :published. The ID is burned and never reused.
      """

      accept [:rejection_reason]
      require_atomic? false

      change transition_state(:rejected)
      change set_attribute(:rejected_at, &DateTime.utc_now/0)

      change before_action(fn changeset, _context ->
               cve_id =
                 get_in(changeset.data.cve_json || %{}, ["cveMetadata", "cveId"]) ||
                   get_in(changeset.data.reservation_json || %{}, ["cve_id"])

               case MitreCveApi.reject(cve_id) do
                 {:ok, _} -> changeset
                 {:error, reason} -> Ash.Changeset.add_error(changeset, reason)
               end
             end)
    end

    update :mark_rejected do
      description """
      Marks this CVE ID rejected locally without calling MITRE — used when MITRE
      already rejected the ID externally.
      """

      accept [:rejection_reason]

      change transition_state(:rejected)
      change set_attribute(:rejected_at, &DateTime.utc_now/0)
    end

    action :top_up_pool, OkResult do
      description """
      Ensures the open pool for the given year meets the configured minimum size.
      Defaults to the current year. Reserves additional IDs from MITRE if needed.

      With skip_on_empty (set by the scheduled run), a completely empty database
      is left untouched: an empty table usually means the first
      sync_reserved_from_mitre has not run yet, and reserving would create
      duplicates of IDs that already exist at MITRE. On a genuinely new MITRE
      account, trigger this action manually once (skip_on_empty defaults to
      false) to bootstrap the pool.
      """

      argument :year, :integer do
        allow_nil? true
        description "The CVE year to top up. Defaults to the current year."
      end

      argument :skip_on_empty, :boolean do
        allow_nil? true
        default false
        description "Skip (no MITRE call) when no CVE records exist locally at all."
      end

      run fn input, _context ->
        skip_on_empty = input.arguments[:skip_on_empty]

        if skip_on_empty and Ash.count!(__MODULE__, authorize?: false) == 0 do
          {:ok, :ok}
        else
          year = input.arguments[:year] || Date.utc_today().year
          min_size = Application.get_env(:cve_management, :cve_pool_min_size, 10)

          open_count =
            __MODULE__
            |> Ash.Query.for_read(:available, %{year: year}, authorize?: false)
            |> Ash.count!(authorize?: false)

          if open_count < min_size do
            amount = min_size - open_count

            case MitreCveApi.reserve(year, amount) do
              {:ok, reservation_jsons} ->
                inputs = Enum.map(reservation_jsons, &%{reservation_json: &1})

                Ash.bulk_create!(inputs, __MODULE__, :reserve, authorize?: false)

              {:error, reason} ->
                raise "Failed to reserve CVE IDs from MITRE: #{reason}"
            end
          end

          {:ok, :ok}
        end
      end
    end

    action :sync_reserved_from_mitre, OkResult do
      description """
      Upserts IDs currently RESERVED at MITRE (catching external reservations) and
      marks local pool rows rejected whose IDs MITRE has already rejected externally.
      IDs published externally are picked up by the import_from_mitre action instead.
      """

      run fn _input, _context ->
        # 1. Upsert all RESERVED IDs from MITRE
        MitreCveApi.stream_reserved_ids()
        |> Stream.map(&%{reservation_json: &1})
        |> Stream.chunk_every(100)
        |> Enum.each(fn chunk ->
          Ash.bulk_create!(chunk, __MODULE__, :reserve, authorize?: false)
        end)

        # 2. Mark local pool rows rejected for IDs that MITRE has rejected externally.
        #    Only un-published pool rows are affected; published records are left intact.
        Enum.each(MitreCveApi.stream_rejected_ids(), fn rejected_cve_id ->
          reject_pool_row(rejected_cve_id, "Rejected externally at MITRE")
        end)

        {:ok, :ok}
      end
    end

    action :run_reject_stale, OkResult do
      description """
      Scheduled entry point for stale rejection. Runs Feb 1st each year.
      Rejects all open prior-year reservations at MITRE via :reject.
      """

      run fn _input, _context ->
        current_year = Date.utc_today().year
        current_year_start = DateTime.new!(Date.new!(current_year, 1, 1), ~T[00:00:00])

        __MODULE__
        |> Ash.Query.filter(state == :reserved and reserved_at < ^current_year_start)
        |> Ash.bulk_update!(:reject, %{rejection_reason: "Stale prior-year reservation"},
          authorize?: false,
          return_errors?: true,
          strategy: :stream,
          allow_stream_with: :full_read
        )

        {:ok, :ok}
      end
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

  validations do
    # Records are only required to be valid when handed to MITRE; earlier
    # lifecycle states may hold incomplete or invalid JSON.
    validate ValidCveRecord do
      where action_is([:request_publish, :update])
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :reservation_json, :map do
      description "Raw MITRE reservation object. Present from the :reserved state onward."
      public? true
    end

    attribute :cve_json, :map do
      description "Full MITRE CVE record. Populated once the record is published."
      public? true
    end

    attribute :last_synced_at, :utc_datetime do
      public? true
    end

    attribute :rejected_at, :utc_datetime do
      description "When this CVE ID was rejected at MITRE."
      public? true
    end

    attribute :rejection_reason, :string do
      description "Why this CVE ID was rejected."
      public? true
    end

    timestamps()
  end

  calculations do
    calculate :cve_id,
              :string,
              expr(
                fragment(
                  "coalesce(?->'cveMetadata'->>'cveId', ?->>'cve_id')",
                  cve_json,
                  reservation_json
                )
              ) do
      public? true
    end

    calculate :title, :string, expr(fragment("?->'containers'->'cna'->>'title'", cve_json)) do
      public? true
    end

    calculate :reserved_at,
              :utc_datetime,
              expr(fragment("(?->>'reserved')::timestamptz", reservation_json)) do
      public? true
    end

    calculate :year,
              :integer,
              expr(fragment("(?->>'cve_year')::integer", reservation_json)) do
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

    calculate :purls,
              {:array, :string},
              expr(
                fragment(
                  "ARRAY(SELECT a->>'packageURL' FROM jsonb_array_elements(coalesce(?->'containers'->'cna'->'affected', '[]'::jsonb)) AS a WHERE a->>'packageURL' IS NOT NULL)",
                  cve_json
                )
              ) do
      public? true
    end

    calculate :matches_query,
              :boolean,
              expr(fragment("search_vector @@ plainto_tsquery('english', ?)", ^arg(:query))) do
      public? false

      argument :query, :string do
        allow_nil? false
      end
    end
  end

  identities do
    identity :unique_cve_id, [:cve_id]
  end

  defp reject_pool_row(cve_id, reason) do
    __MODULE__
    |> Ash.Query.filter(cve_id == ^cve_id and state == :reserved)
    |> Ash.bulk_update!(:mark_rejected, %{rejection_reason: reason},
      authorize?: false,
      return_errors?: true,
      strategy: :stream,
      allow_stream_with: :full_read
    )

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
