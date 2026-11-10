# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

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
    reserved --> withheld : withhold (user)
    reserved --> rejected : reject (stale / external)
    withheld --> draft : assign (named explicitly)
    withheld --> published : import (published elsewhere)
    withheld --> rejected : reject
    draft --> publishing : request_publish (user)
    draft --> reserved : release (user / case close)
    draft --> rejected : reject
    publishing --> published : publish (Oban)
    published --> pending_update : update (user)
    published --> rejected : reject
    pending_update --> published : push_update (Oban)
  ```

  | State | Meaning |
  | --- | --- |
  | `reserved` | Reserved from MITRE, open in the pool |
  | `withheld` | Withheld from the pool for use outside this system |
  | `draft` | Taken out of the pool for drafting, not yet published |
  | `publishing` | Publish job enqueued; pushing the CNA container to MITRE |
  | `published` | MITRE accepted the record; `cve_json` set |
  | `pending_update` | Local edits to `cve_json` awaiting push to MITRE |
  | `rejected` | Terminal — rejected at MITRE; the ID is burned and never reused |

  ## Upstream CVEs

  A package can vendor code from a project outside this CNA's scope, such as
  a C library. The CNA Operational Rules forbid this CNA to assign a CVE for
  a vulnerability in that code: the CNA responsible for the vendored project
  assigns it. A case may instead enrich that upstream CVE for the affected
  packages. Such a row has `upstream` set and uses only these transitions:

  ```mermaid
  stateDiagram-v2
    [*] --> draft : link_upstream
    draft --> published : publish_enrichment
    published --> published : publish_enrichment
    draft --> rejected : sync_upstream (Oban)
    published --> rejected : sync_upstream (Oban)
  ```

  Another CNA owns the ID, so every action that writes to MITRE or to the
  pool refuses an upstream row. `cve_json` holds MITRE's record and stays
  empty while the upstream ID is RESERVED. This CNA's enrichment is its ADP
  container in that record (see `Varsel.CVE.OwnContainer`), which
  `sync_upstream` keeps when it adopts a newer record from MITRE.
  Search, purl lookup and CWE filters read every container of a record.
  Titles, purls and CVSS scores in listings come from `content_container`,
  the container this CNA authored. The publication statistics count only the
  CVEs this CNA assigned.

  At MITRE `reserved`, `withheld` and `draft` are all simply `RESERVED`; the
  distinction is purely local. A `draft` returns to the open pool only through
  `release`: by hand when no case holds it, or when its case closes without
  rejecting it.

  `withheld` marks an ID spoken for outside this system — the primary case being
  the migration period, where the old management system still hands out IDs from
  the same MITRE pool. A withheld ID is never *offered*: it stays out of the open
  pool, so nothing auto-picks it for a case or counts it toward a pool top-up.

  It leaves the state three ways: the MITRE sync finds it published and imports
  the record (unlike `draft`, it is not blocked from that import — whoever
  published it did so outside this system, so the incoming record is the first
  thing we know about it); someone discards it (`reject`); or someone names it
  explicitly when assigning a case, which pulls it back into `draft`. Only the
  last is a deliberate reversal of the hold — auto-assignment can never reach it.

  ## Actions

  - `:reserve` (create) — Inserts/upserts a pool entry in the `:reserved` state from a
    raw MITRE reservation object.

  - `:import` — Upserts a record directly into the `:published` state from a full MITRE
    record. Used by the scheduled `import_from_mitre` action. Only new rows and rows in
    `:reserved`, `:withheld` or `:published` are written; in-flight local work and
    `:rejected` tombstones are never overwritten (upsert_condition).

  - `:assign` (update) — Transitions a `:reserved` record to `:draft`, taking it out of
    the open pool.

  - `:release` (update) — Transitions a `:draft` record back to `:reserved`. Refused
    while a case holds the ID; closing a case releases its own drafted ID.

  - `:withhold` (update) — Transitions a `:reserved` record to `:withheld`, holding the ID
    for use outside this system so nothing here assigns it. Requires a non-blank
    `withhold_reason`.

  - `:request_publish` (update) — Accepts the `cve_json` for a `:draft` record, transitions
    it to `:publishing`, and enqueues a publish job. The Oban `:publish` worker then calls
    the MITRE API to submit the CNA container and transitions the record to `:published`.

  - `:update` (update) — Transitions a `:published` record to `:pending_update` with new
    `cve_json` and enqueues a push_update job.

  - `:reject` (update) — Transitions a `:reserved`, `:withheld`, `:draft`, or `:published`
    record to the terminal `:rejected` state, rejecting the ID at MITRE and recording the
    reason.

  - `:import_from_mitre` / `:sync_from_mitre` — Scheduled daily; keep published records
    in sync with MITRE.

  - `:top_up_pool` / `:sync_reserved_from_mitre` / `:run_reject_stale` — Scheduled pool
    maintenance (see ADR-014).

  - `:link_upstream` (create) / `:sync_upstream` / `:publish_enrichment` /
    `:unlink_upstream` (destroy) — The upstream CVE lifecycle (see above).

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
    notifiers: [Ash.Notifier.PubSub]

  import Ash.Expr

  alias Varsel.CVE.CveRecord.Actions.ImportFromMitre
  alias Varsel.CVE.CveRecord.Actions.RefillPool
  alias Varsel.CVE.CveRecord.Actions.RunRejectStale
  alias Varsel.CVE.CveRecord.Actions.SyncReservedFromMitre
  alias Varsel.CVE.CveRecord.Changes.LinkUpstream
  alias Varsel.CVE.CveRecord.Changes.PutEnrichment
  alias Varsel.CVE.CveRecord.Changes.RejectAtMitre
  alias Varsel.CVE.CveRecord.Changes.SetContentContainer
  alias Varsel.CVE.CveRecord.Changes.SyncUpstream
  alias Varsel.CVE.CveRecord.Preparations.FilterByCwe
  alias Varsel.CVE.CveRecord.Validations.ValidCveRecord
  alias Varsel.CVE.Signals
  alias Varsel.Types.OkResult

  graphql do
    type :cve_record
  end

  postgres do
    table "cve_records"
    repo Varsel.Repo

    calculations_to_sql cve_id: "coalesce(cve_json->'cveMetadata'->>'cveId', reservation_json->>'cve_id')",
                        title: "content_container->>'title'",
                        reserved_at: "(reservation_json->>'reserved')::timestamptz",
                        date_published: "cve_record_published(cve_json)",
                        year: "(reservation_json->>'cve_year')::integer",
                        search_vector: "search_vector",
                        capec_ids: "cve_record_capec_ids(cve_json)"

    # The migration generator cannot express GENERATED ALWAYS.
    migration_ignore_attributes [:search_vector, :cwe_ids]

    custom_statements do
      # The indexes cover every container: the CNA's and each ADP's.
      statement :cve_record_containers_fn do
        up """
        CREATE FUNCTION cve_record_containers(cve_json jsonb)
        RETURNS jsonb
        LANGUAGE sql
        IMMUTABLE PARALLEL SAFE
        AS $$
          SELECT jsonb_path_query_array(cve_json, '$.containers.cna')
            || jsonb_path_query_array(cve_json, '$.containers.adp[*]')
        $$
        """

        down "DROP FUNCTION IF EXISTS cve_record_containers(jsonb)"
      end

      statement :cve_record_affected_fn do
        up """
        CREATE FUNCTION cve_record_affected(cve_json jsonb)
        RETURNS jsonb
        LANGUAGE sql
        IMMUTABLE PARALLEL SAFE
        AS $$
          SELECT jsonb_path_query_array(cve_json, '$.containers.cna.affected[*]')
            || jsonb_path_query_array(cve_json, '$.containers.adp[*].affected[*]')
        $$
        """

        down "DROP FUNCTION IF EXISTS cve_record_affected(jsonb)"
      end

      statement :cve_record_search_vector_fn do
        up """
        CREATE FUNCTION cve_record_search_vector(cve_json jsonb)
        RETURNS tsvector
        LANGUAGE sql
        IMMUTABLE PARALLEL SAFE
        AS $$
          SELECT
            setweight(to_tsvector('english', coalesce(cve_json->'cveMetadata'->>'cveId', '')), 'A') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(c->>'title', ' ')
               FROM jsonb_array_elements(public.cve_record_containers(cve_json)) AS c),
              ''
            )), 'A') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(d->>'value', ' ')
               FROM jsonb_array_elements(public.cve_record_containers(cve_json)) AS c,
                    jsonb_array_elements(coalesce(c->'descriptions', '[]'::jsonb)) AS d),
              ''
            )), 'B') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(
                 coalesce(a->>'packageName', '') || ' ' ||
                 coalesce(a->>'product', '') || ' ' ||
                 coalesce(a->>'vendor', ''),
                 ' ')
               FROM jsonb_array_elements(public.cve_record_affected(cve_json)) AS a),
              ''
            )), 'B') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(w->>'value', ' ')
               FROM jsonb_array_elements(public.cve_record_containers(cve_json)) AS c,
                    jsonb_array_elements(coalesce(c->'workarounds', '[]'::jsonb)) AS w),
              ''
            )), 'C') ||
            setweight(to_tsvector('english', coalesce(
              (SELECT string_agg(g->>'value', ' ')
               FROM jsonb_array_elements(public.cve_record_containers(cve_json)) AS c,
                    jsonb_array_elements(coalesce(c->'configurations', '[]'::jsonb)) AS g),
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

      statement :cve_record_published_fn do
        up """
        CREATE FUNCTION cve_record_published(cve_json jsonb)
        RETURNS timestamp
        LANGUAGE sql
        IMMUTABLE PARALLEL SAFE
        AS $$
          SELECT (cve_json->'cveMetadata'->>'datePublished')::timestamp
        $$
        """

        down "DROP FUNCTION IF EXISTS cve_record_published(jsonb)"
      end

      statement :cve_record_published_quarter_fn do
        up """
        CREATE FUNCTION cve_record_published_quarter(cve_json jsonb)
        RETURNS date
        LANGUAGE sql
        IMMUTABLE PARALLEL SAFE
        AS $$
          SELECT date_trunc('quarter', (cve_json->'cveMetadata'->>'datePublished')::timestamp)::date
        $$
        """

        down "DROP FUNCTION IF EXISTS cve_record_published_quarter(jsonb)"
      end

      statement :add_published_index do
        up "CREATE INDEX cve_records_published ON cve_records (cve_record_published(cve_json)) WHERE state = 'published'"
        down "DROP INDEX IF EXISTS cve_records_published"
      end

      statement :add_published_quarter_index do
        up "CREATE INDEX cve_records_published_quarter ON cve_records (cve_record_published_quarter(cve_json)) WHERE state = 'published'"
        down "DROP INDEX IF EXISTS cve_records_published_quarter"
      end

      statement :add_search_vector_gin_index do
        up "CREATE INDEX cve_records_search_vector_gin ON cve_records USING GIN (search_vector)"
        down "DROP INDEX IF EXISTS cve_records_search_vector_gin"
      end

      statement :add_affected_gin_index do
        up "CREATE INDEX cve_records_affected_gin ON cve_records USING GIN (cve_record_affected(cve_json))"
        down "DROP INDEX IF EXISTS cve_records_affected_gin"
      end

      statement :cve_record_cwe_ids_fn do
        up """
        CREATE FUNCTION cve_record_cwe_ids(document jsonb)
        RETURNS bigint[]
        LANGUAGE sql
        IMMUTABLE
        PARALLEL SAFE
        STRICT
        AS $$
          SELECT COALESCE(
            array_agg(DISTINCT cwe_id ORDER BY cwe_id),
            ARRAY[]::bigint[]
          )
          FROM jsonb_array_elements(public.cve_record_containers(document)) AS container
          CROSS JOIN LATERAL jsonb_array_elements(
            COALESCE(
              container -> 'problemTypes',
              '[]'::jsonb
            )
          ) AS problem_type
          CROSS JOIN LATERAL jsonb_array_elements(
            COALESCE(
              problem_type -> 'descriptions',
              '[]'::jsonb
            )
          ) AS description
          CROSS JOIN LATERAL (
            SELECT (regexp_match(description ->> 'cweId', '^CWE-([0-9]+)$'))[1]::bigint AS cwe_id
          ) AS extracted
          WHERE cwe_id IS NOT NULL;
        $$;
        """

        down "DROP FUNCTION IF EXISTS cve_record_cwe_ids(jsonb)"
      end

      # A read-time call of cve_record_cwe_ids gets JIT-compiled once per row on
      # PostgreSQL 17, at several milliseconds each.
      statement :add_cwe_ids do
        up "ALTER TABLE cve_records ADD COLUMN cwe_ids bigint[] GENERATED ALWAYS AS (cve_record_cwe_ids(cve_json)) STORED"
        down "ALTER TABLE cve_records DROP COLUMN IF EXISTS cwe_ids"
      end

      statement :add_cwe_ids_index_v3 do
        up "CREATE INDEX cve_records_cwe_ids ON cve_records USING GIN (cwe_ids)"
        down "DROP INDEX IF EXISTS cve_records_cwe_ids"
      end

      statement :cve_record_capec_ids_fn do
        up """
        CREATE FUNCTION cve_record_capec_ids(document jsonb)
        RETURNS bigint[]
        LANGUAGE sql
        IMMUTABLE
        PARALLEL SAFE
        STRICT
        AS $$
          SELECT COALESCE(
            array_agg(DISTINCT capec_id ORDER BY capec_id),
            ARRAY[]::bigint[]
          )
          FROM jsonb_array_elements(public.cve_record_containers(document)) AS container
          CROSS JOIN LATERAL jsonb_array_elements(
            COALESCE(
              container -> 'impacts',
              '[]'::jsonb
            )
          ) AS impact
          CROSS JOIN LATERAL (
            SELECT (regexp_match(impact ->> 'capecId', '^CAPEC-([0-9]+)$'))[1]::bigint AS capec_id
          ) AS extracted
          WHERE capec_id IS NOT NULL;
        $$;
        """

        down "DROP FUNCTION IF EXISTS cve_record_capec_ids(jsonb)"
      end

      statement :add_capec_ids_index_v2 do
        up "CREATE INDEX cve_records_capec_ids ON cve_records USING GIN (cve_record_capec_ids(cve_json))"
        down "DROP INDEX IF EXISTS cve_records_capec_ids"
      end
    end
  end

  state_machine do
    initial_states [:reserved, :published, :draft]
    default_initial_state :reserved

    transitions do
      transition :assign, from: [:reserved, :withheld], to: :draft
      transition :release, from: :draft, to: :reserved
      transition :withhold, from: :reserved, to: :withheld
      transition :request_publish, from: :draft, to: :publishing
      transition :publish, from: :publishing, to: :published
      transition :update, from: :published, to: :pending_update
      transition :update, from: :pending_update, to: :pending_update
      transition :push_update, from: :pending_update, to: :published
      transition :reject, from: [:reserved, :withheld, :draft, :published], to: :rejected
      transition :mark_rejected, from: [:reserved, :withheld, :draft, :published], to: :rejected
      transition :sync_upstream, from: [:draft, :published], to: :rejected
      transition :publish_enrichment, from: [:draft, :published], to: :published
    end
  end

  oban do
    triggers do
      trigger :publish do
        action :publish
        where expr(state == :publishing and not upstream)
        worker_module_name Varsel.CVE.CveRecord.PublishWorker
        scheduler_module_name Varsel.CVE.CveRecord.PublishScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end

      trigger :push_update do
        action :push_update
        where expr(state == :pending_update and not upstream)
        worker_module_name Varsel.CVE.CveRecord.PushUpdateWorker
        scheduler_module_name Varsel.CVE.CveRecord.PushUpdateScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end

      trigger :sync_from_mitre do
        action :sync_from_mitre
        where expr(state == :published and not upstream)
        worker_module_name Varsel.CVE.CveRecord.SyncFromMitreWorker
        scheduler_module_name Varsel.CVE.CveRecord.SyncFromMitreScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "0 2 * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end

      # Hourly so an embargoed upstream CVE unblocks its case soon after the
      # upstream CNA publishes it.
      trigger :sync_upstream do
        action :sync_upstream
        where expr(upstream and state in [:draft, :published])
        worker_module_name Varsel.CVE.CveRecord.SyncUpstreamWorker
        scheduler_module_name Varsel.CVE.CveRecord.SyncUpstreamScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "0 * * * *"
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
    reference_source? false
    attributes_as_attributes [:state]
    ignore_attributes [:last_synced_at, :inserted_at, :updated_at, :version]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    read :list_published do
      description """
      Lists published CVE records, newest first. Optionally filtered to a
      single CWE (or, with view_id, its whole closure subtree).
      """

      argument :cwe_id, :integer do
        allow_nil? true

        description """
        Only CVEs directly assigned this CWE (numeric id). Combined with
        view_id, matches the whole subtree instead.
        """
      end

      argument :view_id, :integer do
        allow_nil? true

        description """
        CWE view scoping the recursive filter; with no cwe_id, matches CVEs
        with any CWE in the view.
        """
      end

      prepare build(
                load: [:cve_id, :title, :date_published, :date_updated, :purls],
                sort: [date_published: :desc]
              )

      prepare FilterByCwe

      filter expr(state == :published)

      pagination offset?: true,
                 keyset?: true,
                 countable: :by_default,
                 default_limit: 25,
                 required?: false
    end

    action :published_quarter_counts, {:array, :tuple} do
      description "Counts published CVE records per calendar quarter of publication."

      constraints items: [
                    fields: [
                      quarter: [type: :date, allow_nil?: false],
                      count: [type: :integer, allow_nil?: false]
                    ]
                  ]

      run Varsel.CVE.CveRecord.Actions.PublishedQuarterCounts
    end

    action :published_cwe_subtree_counts, {:array, :tuple} do
      description """
      Counts published CVE records recursively reachable under each of a set
      of CWE ids, scoped to one view. Parents with zero matching CVEs are
      absent from the result, not zero-valued rows.
      """

      public? false

      constraints items: [
                    fields: [
                      cwe_id: [type: :integer, allow_nil?: false],
                      count: [type: :integer, allow_nil?: false]
                    ]
                  ]

      argument :view_id, :integer, allow_nil?: false

      argument :cwe_ids, {:array, :integer} do
        allow_nil? false
        description "The parents (view members or a CWE's direct children) to count under."
      end

      run Varsel.CVE.CveRecord.Actions.PublishedCweSubtreeCounts
    end

    action :published_cwe_view_total, :integer do
      description """
      Counts published CVE records recursively reachable under one subject
      within a view — a single CWE's subtree, or (with `cwe_id` absent) the
      whole view. Unlike summing `published_cwe_subtree_counts` results,
      this never over- or under-counts: sibling subtrees can overlap, and a
      node's own CVEs (or those attached between it and its ancestors)
      never appear in any child's slice count.
      """

      public? false

      argument :view_id, :integer, allow_nil?: false

      argument :cwe_id, :integer do
        allow_nil? true

        description "The subtree root; omitted means the whole view (its NULL-parent closure rows)."
      end

      run Varsel.CVE.CveRecord.Actions.PublishedCweViewTotal
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

    read :search do
      description """
      Full-text search over CVE ID, title, descriptions, affected packages,
      workarounds, and configurations, best match first. Terms are ANDed by
      default; separate alternatives with OR for broad recall, or wrap an exact
      phrase in double quotes.
      """

      argument :query, :string, allow_nil?: false

      prepare build(load: [:cve_id, :title, :date_published, :date_updated, :purls])
      filter expr(matches_query(query: ^arg(:query)) and state == :published)
      prepare build(sort: [search_rank: {%{query: arg(:query)}, :desc}])
    end

    read :list_by_purl do
      description "Lists published CVE records that affect a given package URL (PURL)."
      argument :purl, :string, allow_nil?: false

      prepare build(load: [:cve_id, :title, :date_published, :date_updated, :purls])

      filter expr(
               fragment(
                 "cve_record_affected(?) @> jsonb_build_array(jsonb_build_object('packageURL', ?::text))",
                 cve_json,
                 ^arg(:purl)
               ) and state == :published
             )
    end

    read :assignable do
      description """
      Every CVE ID a case may take: the open pool plus withheld IDs, which are
      never offered automatically but may be named explicitly. Oldest first;
      grouping free before withheld is left to whoever presents them.
      """

      prepare build(load: [:cve_id, :reserved_at], sort: [reserved_at: :asc])

      filter expr(state in [:reserved, :withheld])
    end

    read :available do
      description """
      Returns open (unassigned) reservations in the pool for a given year.
      Withheld IDs are spoken for elsewhere and never appear here.
      """

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
      Rows in :draft, :publishing, :pending_update, or :rejected are never overwritten:
      the upsert_condition turns those upserts into silent skips.
      """

      accept [:cve_json]
      upsert? true
      upsert_identity :unique_cve_id
      upsert_fields [:state, :cve_json, :content_container]

      # In-flight local work (:draft, :publishing, :pending_update) and
      # :rejected tombstones must never be overwritten by the import sweep.
      # A skipped upsert errors (StaleRecord) on single-record use but is
      # silent in the sweep's bulk path.
      #
      # :withheld is deliberately importable: the whole point of withholding an
      # ID is that it gets published outside this system, so the sync finding a
      # published record for it is the expected end of the hold, not a clash
      # with local work.
      upsert_condition expr(state in [:reserved, :withheld, :published])

      change set_attribute(:state, :published)
      emit Signals, :cve_record_published, fields: [cve_record_id: :id]
    end

    action :import_from_mitre, OkResult do
      description """
      Fetches all published CVE IDs from MITRE and imports any that are new locally
      or fill a local :reserved or :withheld row. Rows in any other state are skipped
      with a warning (see the :import upsert_condition).
      """

      run ImportFromMitre
    end

    update :assign do
      description """
      Takes a reserved CVE ID out of the open pool, moving it into the draft state.
      Also valid from :withheld, releasing a held ID back into local work — nothing
      auto-picks a withheld ID, so this only happens when one is named explicitly.
      """

      accept []
      change transition_state(:draft)
      emit Signals, :cve_record_assigned, fields: [cve_record_id: :id]
    end

    update :release do
      description """
      Returns a drafted CVE ID to the open pool. Refused while a case holds
      the ID: closing the case is what lets go of it.
      """

      accept []
      require_atomic? false

      change transition_state(:reserved)
    end

    update :withhold do
      description """
      Withholds a reserved CVE ID for use outside this system — the migration period,
      where the old management system issues IDs from the same MITRE pool, being the
      motivating case. The ID leaves the open pool without being drafted here: nothing
      in this system assigns it, and it stays withheld until it is rejected or the MITRE
      sync imports a published record for it. The reason is required — it is what makes
      the hold reviewable once the migration it was made for is over.
      """

      accept [:withhold_reason]

      # Required and non-blank: a hold can outlive the migration that motivated
      # it, and months later the reason is the only thing that says whether the
      # ID is still spoken for or was simply forgotten. Ash casts "" to nil
      # before validation, so `present` is what rejects a blank submission —
      # string_length alone would let it through.
      validate present(:withhold_reason)
      validate string_length(:withhold_reason, min: 1)

      change transition_state(:withheld)
      change set_attribute(:withheld_at, &DateTime.utc_now/0)
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
      emit Signals, :cve_record_published, fields: [cve_record_id: :id]
    end

    update :sync_from_mitre do
      description "Oban worker action: pulls the latest record from MITRE, adopting it only when newer."
      accept []
      require_atomic? false

      change Varsel.CVE.CveRecord.Changes.SyncFromMitre

      emit Signals, :cve_record_published,
        fields: [cve_record_id: :id],
        where: [changing(:cve_json)]
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
      emit Signals, :cve_record_published, fields: [cve_record_id: :id]
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

      change RejectAtMitre
      emit Signals, :cve_record_rejected, fields: [cve_record_id: :id]
    end

    update :mark_rejected do
      description """
      Marks this CVE ID rejected locally without calling MITRE — used when MITRE
      already rejected the ID externally.
      """

      accept [:rejection_reason]

      change transition_state(:rejected)
      change set_attribute(:rejected_at, &DateTime.utc_now/0)
      emit Signals, :cve_record_rejected, fields: [cve_record_id: :id]
    end

    create :link_upstream do
      description """
      Tracks a CVE ID that another CNA assigned, so a case can publish an
      enrichment for it. MITRE must hold the ID as RESERVED or PUBLISHED, and
      another org must own it. The row enters :draft with `upstream` set, and
      with its full record when the ID is PUBLISHED.
      """

      argument :cve_id, :string do
        allow_nil? false
        description "The upstream CVE ID, e.g. CVE-2026-111497."
      end

      validate match(:cve_id, ~r/\ACVE-\d{4}-\d{4,19}\z/) do
        message "must be a CVE ID like CVE-2026-12345"
      end

      change LinkUpstream
    end

    update :sync_upstream do
      description """
      Oban worker action: refreshes an upstream CVE from MITRE. Fills
      `cve_json` once the upstream CNA publishes, adopts newer records, and
      moves the row to :rejected once MITRE rejects the ID.
      """

      accept []
      require_atomic? false

      change SyncUpstream

      emit Signals, :cve_record_published,
        fields: [cve_record_id: :id],
        where: [changing(:cve_json), attribute_equals(:state, :published)]

      emit Signals, :cve_record_rejected,
        fields: [cve_record_id: :id],
        where: [attribute_equals(:state, :rejected)]
    end

    update :publish_enrichment do
      description """
      Puts this CNA's ADP container into an upstream CVE's record and makes
      the enrichment public. Refused while the upstream ID is RESERVED.
      Nothing is sent to MITRE.
      """

      accept []
      require_atomic? false

      argument :adp_container, :map do
        allow_nil? false
        description "This CNA's ADP container. Its providerMetadata is set to this CNA's."
      end

      validate present(:cve_json) do
        message "the upstream CVE is not published at MITRE yet"
      end

      change PutEnrichment
      change transition_state(:published)
      validate ValidCveRecord
      emit Signals, :cve_record_published, fields: [cve_record_id: :id]
    end

    destroy :unlink_upstream do
      description """
      Stops tracking an upstream CVE whose enrichment was never published.
      A published enrichment stays, like any published record.
      """

      require_atomic? false
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

      argument :signal, Signals.CveRecordAssigned do
        description "The assignment that took an ID out of the pool, when one runs the top-up."
        allow_nil? true
      end

      run RefillPool
    end

    action :sync_reserved_from_mitre, OkResult do
      description """
      Upserts IDs currently RESERVED at MITRE (catching external reservations) and
      marks local pool rows rejected whose IDs MITRE has already rejected externally.
      IDs published externally are picked up by the import_from_mitre action instead.
      """

      run SyncReservedFromMitre
    end

    action :run_reject_stale, OkResult do
      description """
      Scheduled entry point for stale rejection. Runs Feb 1st each year.
      Rejects all open prior-year reservations at MITRE via :reject.
      """

      run RunRejectStale
    end
  end

  policies do
    # Pre-flight visibility only (`Ash.can?`): at runtime this passes and the
    # `transition_state` validation stays the enforcement.
    policy action_type(:update) do
      authorize_if AshStateMachine.Checks.ValidNextState
    end

    # Another CNA owns an upstream ID, so MITRE and the pool are not this
    # CNA's to write for it. Above the bypass, so it binds the Oban workers.
    policy action([
             :assign,
             :release,
             :withhold,
             :request_publish,
             :publish,
             :update,
             :push_update,
             :reject
           ]) do
      forbid_if expr(upstream)
      authorize_if always()
    end

    policy action([:sync_upstream, :publish_enrichment]) do
      authorize_if expr(upstream)
    end

    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    # Public/anonymous reads only ever return published records; a POC actor
    # bypasses the published filter (the first check short-circuits the block,
    # so the whole read is authorized regardless of state).
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if context_equals([:private, :assign_cve_id?], true)
      authorize_if expr(state == :published)
    end

    # Counts only published records, which the read policy above serves to
    # anyone.
    policy action(:published_quarter_counts) do
      authorize_if always()
    end

    # Count only published records, same as published_quarter_counts —
    # public aggregate data regardless of actor.
    policy action([:published_cwe_subtree_counts, :published_cwe_view_total]) do
      authorize_if always()
    end

    # POC-only admin lifecycle actions, used by the CVE-management LiveView.
    # The three MITRE sync actions also run on the nightly schedule through the
    # AshOban bypass.
    policy action([
             :withhold,
             :request_publish,
             :update,
             :reject,
             :import_from_mitre,
             :sync_from_mitre,
             :sync_reserved_from_mitre,
             :link_upstream,
             :sync_upstream,
             :publish_enrichment
           ]) do
      authorize_if actor_attribute_equals(:role, :poc)
    end

    # A published enrichment is public data and stays, like a published CVE.
    policy action(:unlink_upstream) do
      forbid_unless actor_attribute_equals(:role, :poc)
      authorize_if expr(upstream and state == :draft)
    end

    # An ID a case holds returns to the pool through that case's close.
    policy action(:release) do
      forbid_unless actor_attribute_equals(:role, :poc)
      authorize_if expr(is_nil(case.id))
    end

    policy action(:assign) do
      authorize_if actor_attribute_equals(:role, :poc)
      forbid_unless context_equals([:private, :assign_cve_id?], true)
      authorize_if actor_attribute_equals(:role, :supporter)
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

  changes do
    # Updates always run against server-loaded snapshots. Rejecting any write
    # whose row moved since that load (StaleRecord) is what entitles
    # `transition_state` and the update policies to trust `changeset.data`.
    # No exemptions: no CveRecord update runs nested inside another update on
    # the same row (the Oban worker changes mutate the current changeset only).
    change optimistic_lock(:version), on: [:update]

    change SetContentContainer, on: [:create, :update]
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

    attribute :version, :integer do
      description "Optimistic lock counter; every update bumps it and rejects stale snapshots."
      allow_nil? false
      default 1
      public? false
    end

    attribute :search_vector, Varsel.Types.TSVector do
      writable? false
      public? false
      generated? true
      select_by_default? false
    end

    attribute :cwe_ids, {:array, :integer} do
      writable? false
      public? true
      generated? true
      select_by_default? false
    end

    attribute :reservation_json, :map do
      description "Raw MITRE reservation object. Present from the :reserved state onward."
      public? true
    end

    attribute :cve_json, :map do
      description "Full MITRE CVE record. Populated once the record is published."
      public? true
    end

    attribute :upstream, :boolean do
      description "Another CNA assigned this CVE ID. This CNA only publishes an enrichment for it."
      allow_nil? false
      default false
      public? true
    end

    attribute :content_container, :map do
      description """
      The container this CNA authored in `cve_json`, as `Varsel.CVE.OwnContainer.get/1`
      finds it. The values the UI shows come from it.
      """

      writable? false
      public? false
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

    attribute :withheld_at, :utc_datetime do
      description "When this CVE ID was withheld from the pool."
      public? true
    end

    attribute :withhold_reason, :string do
      description "What this CVE ID is being held for outside this system."
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

  # Unique by listener alone, so a burst of assignments collapses into one
  # waiting job. An executing job does not count: it may have counted the pool
  # before the newest assignment committed.
  signals_in do
    from Signals do
      on :cve_record_assigned, :top_up_pool,
        delivery:
          {AshOban.Signals,
           queue: :cve_pool, max_attempts: 3, unique: [keys: [], states: [:available, :scheduled, :retryable]]}
    end
  end

  calculations do
    calculate :validation,
              Varsel.CVE.CveValidation.Result,
              Varsel.CVE.CveRecord.Calculations.Validation do
      public? true
      filterable? false

      description """
      The schema/cvelint/hex validation result (`valid` + `errors`) for the
      record's stored cve_json, or nil for a record that has no cve_json yet.
      """
    end

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

    calculate :title, :string, expr(fragment("?->>'title'", content_container)) do
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

    calculate :published_quarter,
              :date,
              expr(fragment("cve_record_published_quarter(?)", cve_json)) do
      public? true
    end

    calculate :date_published,
              :utc_datetime,
              expr(
                fragment(
                  "cve_record_published(?)",
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
                  "ARRAY(SELECT a->>'packageURL' FROM jsonb_array_elements(coalesce(?->'affected', '[]'::jsonb)) AS a WHERE a->>'packageURL' IS NOT NULL)",
                  content_container
                )
              ) do
      public? true
    end

    calculate :cvss,
              Varsel.Types.CVSS,
              expr(
                fragment(
                  """
                  coalesce(
                    jsonb_path_query_first(?, '$.metrics[*].cvssV4_0.vectorString'),
                    jsonb_path_query_first(?, '$.metrics[*].cvssV3_1.vectorString'),
                    jsonb_path_query_first(?, '$.metrics[*].cvssV3_0.vectorString')
                  )
                  """,
                  content_container,
                  content_container,
                  content_container
                )
              ) do
      public? true
    end

    # websearch_to_tsquery (not plainto_): tolerates arbitrary user input
    # without raising, and honors OR / quoted-phrase operators the caller may
    # pass for broader recall.
    calculate :matches_query,
              :boolean,
              expr(fragment("? @@ websearch_to_tsquery('english', ?)", search_vector, ^arg(:query))) do
      public? false

      argument :query, :string do
        allow_nil? false
      end
    end

    calculate :search_rank,
              :float,
              expr(
                fragment(
                  "ts_rank(?, websearch_to_tsquery('english', ?))",
                  search_vector,
                  ^arg(:query)
                )
              ) do
      public? false

      argument :query, :string do
        allow_nil? false
      end
    end

    calculate :capec_ids,
              {:array, :integer},
              expr(fragment("cve_record_capec_ids(?)", cve_json)) do
      public? true
    end

    # The @> containment operator lets the GIN index cve_records_cwe_ids match.
    calculate :has_cwe,
              :boolean,
              expr(
                fragment(
                  "? @> ARRAY[?::bigint]",
                  cwe_ids,
                  type(^arg(:cwe_id), :integer)
                )
              ) do
      public? false

      argument :cwe_id, :integer do
        allow_nil? false
      end
    end

    # Uncorrelated scalar subquery (planned as an InitPlan) intersected with
    # the outer cwe_ids via &&, so the GIN index still applies to the outer
    # column. A nil cwe_id means the view root: the NULL-parent closure rows,
    # which cover every CWE anywhere in the view.
    calculate :has_cwe_recursively,
              :boolean,
              expr(
                fragment(
                  """
                  ? && (
                    SELECT coalesce(array_agg(c.descendant_cwe_id), ARRAY[]::bigint[])
                    FROM cwe_weakness_closure AS c
                    WHERE c.view_id = ?
                      AND ((?::bigint IS NULL AND c.parent_cwe_id IS NULL) OR c.parent_cwe_id = ?)
                  )
                  """,
                  cwe_ids,
                  type(^arg(:view_id), :integer),
                  type(^arg(:cwe_id), :integer),
                  type(^arg(:cwe_id), :integer)
                )
              ) do
      public? false

      argument :view_id, :integer do
        allow_nil? false
      end

      argument :cwe_id, :integer do
        allow_nil? true
      end
    end
  end

  identities do
    identity :unique_cve_id, [:cve_id]
  end
end
