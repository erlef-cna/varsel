# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.OkResult do
  @moduledoc false
  use Ash.Type.Enum, values: [:ok]
end

defmodule Varsel.CVE.CveRecord do
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

  Published records additionally have a derived OSV document; that lifecycle lives
  entirely on `Varsel.CVE.OsvRecord`, which observes this resource through
  its own Oban triggers.
  """
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CVE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshStateMachine, AshOban, AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Varsel.CVE.OsvRecord.Notifier, Varsel.Cases.Case.Notifier, Ash.Notifier.PubSub]

  import Ash.Expr

  alias Varsel.CVE.CveRecord.OkResult
  alias Varsel.CVE.CveRecord.Validations.ValidCveRecord
  alias Varsel.CVE.MitreCveApi

  require Ash.Query

  graphql do
    type :cve_record
  end

  postgres do
    table "cve_records"
    repo Varsel.Repo

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
        worker_module_name Varsel.CVE.CveRecord.PublishWorker
        scheduler_module_name Varsel.CVE.CveRecord.PublishScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end

      trigger :push_update do
        action :push_update
        where expr(state == :pending_update)
        worker_module_name Varsel.CVE.CveRecord.PushUpdateWorker
        scheduler_module_name Varsel.CVE.CveRecord.PushUpdateScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end

      trigger :sync_from_mitre do
        action :sync_from_mitre
        where expr(state == :published)
        worker_module_name Varsel.CVE.CveRecord.SyncFromMitreWorker
        scheduler_module_name Varsel.CVE.CveRecord.SyncFromMitreScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "0 2 * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end

    scheduled_actions do
      schedule :import_from_mitre, "0 2 * * *",
        action: :import_from_mitre,
        worker_module_name: Varsel.CVE.CveRecord.ImportFromMitreWorker,
        queue: :cve_publishing,
        max_attempts: 3

      # skip_on_empty prevents the scheduled run from reserving IDs before the
      # first MITRE sync on a fresh database — the pool must be bootstrapped by
      # triggering :top_up_pool manually once (see the action's description).
      schedule :top_up_pool, "*/15 * * * *",
        action: :top_up_pool,
        action_input: %{skip_on_empty: true},
        worker_module_name: Varsel.CVE.CveRecord.TopUpPoolWorker,
        queue: :cve_pool,
        max_attempts: 3

      schedule :sync_reserved_from_mitre, "0 3 * * *",
        action: :sync_reserved_from_mitre,
        worker_module_name: Varsel.CVE.CveRecord.SyncReservedFromMitreWorker,
        queue: :cve_pool,
        max_attempts: 3

      schedule :reject_stale, "0 4 1 2 *",
        action: :run_reject_stale,
        worker_module_name: Varsel.CVE.CveRecord.RejectStaleWorker,
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
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
  end

  actions do
    defaults [:read]

    read :list_published do
      description "Lists published CVE records, newest first."

      prepare build(
                load: [:cve_id, :title, :date_published, :date_updated],
                sort: [date_published: :desc]
              )

      filter expr(state == :published)
    end

    read :list_all do
      description "Admin: lists CVE records in every state. POCs see all states; the read policy filters other actors down to published records."

      prepare build(
                load: [:cve_id, :title, :date_published, :date_updated],
                sort: [state: :asc, date_published: :desc]
              )

      pagination offset?: true,
                 keyset?: true,
                 countable: :by_default,
                 default_limit: 25,
                 required?: false
    end

    read :get_published do
      description "Fetches a single published CVE record by its CVE ID."
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
      primary? true
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

      run fn _input, context ->
        opts = Varsel.ObanContext.forward(context)

        MitreCveApi.stream_ids()
        |> Enum.map(fn cve_id ->
          {:ok, cve_json} = MitreCveApi.get(cve_id)
          %{cve_json: cve_json}
        end)
        |> Enum.chunk_every(100)
        |> Enum.each(fn chunk ->
          Varsel.CVE.import_cve_record!(chunk, opts)
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
      description "Records an updated CNA container for a published CVE and enqueues the push to MITRE."
      primary? true
      accept [:cve_json]
      require_atomic? false
      change transition_state(:pending_update)
      change run_oban_trigger(:push_update)
    end

    update :push_update do
      description "Oban worker action: pushes an updated CNA container to MITRE and re-syncs the record."
      accept []
      require_atomic? false

      change Varsel.CVE.CveRecord.Changes.PushUpdate
    end

    update :sync_from_mitre do
      description "Oban worker action: pulls the latest record from MITRE, adopting it only when newer."
      accept []
      require_atomic? false

      change Varsel.CVE.CveRecord.Changes.SyncFromMitre
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

      change Varsel.CVE.CveRecord.Changes.Publish
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

      run fn input, context ->
        opts = Varsel.ObanContext.forward(context)
        skip_on_empty = input.arguments[:skip_on_empty]

        if skip_on_empty and Ash.count!(__MODULE__, opts) == 0 do
          {:ok, :ok}
        else
          year = input.arguments[:year] || Date.utc_today().year
          min_size = Application.get_env(:varsel, :cve_pool_min_size, 10)

          open_count =
            year
            |> Varsel.CVE.query_to_available_cve_records(opts)
            |> Ash.count!(opts)

          if open_count < min_size do
            amount = min_size - open_count

            case MitreCveApi.reserve(year, amount) do
              {:ok, reservation_jsons} ->
                inputs = Enum.map(reservation_jsons, &%{reservation_json: &1})

                Varsel.CVE.reserve_cve_record!(inputs, opts)

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

      run fn _input, context ->
        opts = Varsel.ObanContext.forward(context)

        # 1. Upsert all RESERVED IDs from MITRE
        MitreCveApi.stream_reserved_ids()
        |> Stream.map(&%{reservation_json: &1})
        |> Stream.chunk_every(100)
        |> Enum.each(fn chunk ->
          Varsel.CVE.reserve_cve_record!(chunk, opts)
        end)

        # 2. Mark local pool rows rejected for IDs that MITRE has rejected externally.
        #    Only un-published pool rows are affected; published records are left intact.
        Enum.each(MitreCveApi.stream_rejected_ids(), fn rejected_cve_id ->
          reject_pool_row(rejected_cve_id, "Rejected externally at MITRE", opts)
        end)

        {:ok, :ok}
      end
    end

    action :run_reject_stale, OkResult do
      description """
      Scheduled entry point for stale rejection. Runs Feb 1st each year.
      Rejects all open prior-year reservations at MITRE via :reject.
      """

      run fn _input, context ->
        opts = Varsel.ObanContext.forward(context)
        current_year = Date.utc_today().year
        current_year_start = DateTime.new!(Date.new!(current_year, 1, 1), ~T[00:00:00])

        __MODULE__
        |> Ash.Query.filter(state == :reserved and reserved_at < ^current_year_start)
        |> Varsel.CVE.reject_cve_record!(
          %{rejection_reason: "Stale prior-year reservation"},
          Keyword.put(opts, :bulk_options,
            return_errors?: true,
            strategy: :stream,
            allow_stream_with: :full_read
          )
        )

        {:ok, :ok}
      end
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    # Public/anonymous reads only ever return published records; a POC actor
    # bypasses the published filter (the first check short-circuits the block,
    # so the whole read is authorized regardless of state).
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(state == :published)
    end

    # POC-only admin lifecycle actions, used by the CVE-management LiveView.
    # The three MITRE sync actions also run on the nightly schedule through the
    # AshOban bypass.
    policy action([
             :assign,
             :request_publish,
             :update,
             :reject,
             :import_from_mitre,
             :sync_from_mitre,
             :sync_reserved_from_mitre
           ]) do
      authorize_if actor_attribute_equals(:role, :poc)
    end

    # Pool population: :reserve and :import are the nested creates the sync
    # generic actions run. They are authorized for a POC (a POC-triggered sync
    # from the console) or the scheduler (the AshOban bypass above). The Oban
    # worker actions :publish, :push_update and :mark_rejected are never invoked
    # directly by a user — only via request_publish/close/reject enqueuing their
    # jobs — so they stay covered by the AshObanInteraction bypass alone.
    policy action([:reserve, :import]) do
      authorize_if actor_attribute_equals(:role, :poc)
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "cve_record"

    # A single stable topic ("cve_record:all") that the CVE-management LiveView
    # subscribes to, so any change to any record (assign, request_publish,
    # update, reject, and the Oban publish/push transitions) re-runs its list
    # query. Every connected POC sees the update without a reload; the query
    # re-applies authorization on refetch.
    publish_all :create, ["all"]
    publish_all :update, ["all"]
    publish_all :destroy, ["all"]
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

  relationships do
    has_one :osv_record, Varsel.CVE.OsvRecord do
      public? true
    end

    has_one :case, Varsel.Cases.Case do
      description "The editorial case this CVE record backs, if any."
      public? true
    end
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

  defp reject_pool_row(cve_id, reason, opts) do
    __MODULE__
    |> Ash.Query.filter(cve_id == ^cve_id and state == :reserved)
    |> Varsel.CVE.mark_cve_record_rejected!(
      %{rejection_reason: reason},
      Keyword.put(opts, :bulk_options,
        return_errors?: true,
        strategy: :stream,
        allow_stream_with: :full_read
      )
    )

    :ok
  end
end
