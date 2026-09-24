# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.AttackPattern do
  @moduledoc """
  Represents a single CAPEC (Common Attack Pattern Enumeration and Classification)
  entry from the MITRE CAPEC catalog.

  Data is synced from https://capec.mitre.org/data/xml/capec_latest.xml on startup
  and weekly thereafter via the `sync_capec_catalog` scheduled action.

  ## Full-text search

  The `search_vector` column is a PostgreSQL `tsvector GENERATED ALWAYS AS ... STORED`
  column defined directly in the migration (not as an Ash attribute). It combines:
  - `name` at weight A (highest relevance)
  - `description` at weight B
  - `extended_description`, `prerequisites`, `mitigations`, `consequences` at weight C

  Query it via the `:search` read action.

  ## If-Modified-Since deduplication

  Before downloading, a HEAD request compares the server's `Last-Modified` header
  against the value stored in `CapecMetadata`. If unchanged, the download is skipped.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CAPEC,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban, AshGraphql.Resource]

  import Ash.Expr

  alias Varsel.CAPEC.AttackPatternRelationship
  alias Varsel.CAPEC.AttackPatternWeakness
  alias Varsel.CAPEC.CatalogSync
  alias Varsel.CWE.Weakness
  alias Varsel.Types.OkResult

  graphql do
    type :attack_pattern
  end

  postgres do
    table "capec_attack_patterns"
    repo Varsel.Repo

    # search_vector is a GENERATED ALWAYS AS tsvector column — read-only, never written.
    calculations_to_sql search_vector: "search_vector"

    custom_statements do
      statement :add_search_vector do
        up """
        ALTER TABLE capec_attack_patterns
        ADD COLUMN search_vector tsvector
        GENERATED ALWAYS AS (
          setweight(to_tsvector('english', coalesce(name, '')), 'A') ||
          setweight(to_tsvector('english', coalesce(description, '')), 'B') ||
          setweight(to_tsvector('english', coalesce(extended_description, '')), 'C') ||
          setweight(to_tsvector('english', coalesce(prerequisites, '')), 'C') ||
          setweight(to_tsvector('english', coalesce(mitigations, '')), 'C') ||
          setweight(to_tsvector('english', coalesce(consequences, '')), 'C')
        ) STORED
        """

        down "ALTER TABLE capec_attack_patterns DROP COLUMN IF EXISTS search_vector"
      end

      statement :add_search_vector_gin_index do
        up "CREATE INDEX capec_attack_patterns_search_vector_gin ON capec_attack_patterns USING GIN (search_vector)"
        down "DROP INDEX IF EXISTS capec_attack_patterns_search_vector_gin"
      end
    end
  end

  oban do
    scheduled_actions do
      schedule :sync_capec_catalog, "0 5 * * 1",
        action: :sync_capec_catalog,
        worker_module_name: Varsel.CAPEC.AttackPattern.SyncCapecCatalogWorker,
        queue: :capec_sync,
        max_attempts: 3

      schedule :sync_capec_catalog_on_boot, "@reboot",
        action: :sync_capec_catalog,
        worker_module_name: Varsel.CAPEC.AttackPattern.SyncCapecCatalogOnBootWorker,
        queue: :capec_sync,
        max_attempts: 3
    end
  end

  actions do
    read :read do
      description "Lists attack patterns with keyset pagination."
      primary? true
      pagination keyset?: true, required?: false
    end

    read :search do
      description """
      Full-text search over name, description, prerequisites, mitigations, and
      consequences, best match first. Bare words are ANDed; `OR` widens (e.g.
      `malformed OR crash OR length OR validation`), `"quoted words"` must
      appear adjacent, and `-word` excludes. Words are stemmed, and no input
      is a syntax error.
      """

      argument :query, :string, allow_nil?: false

      filter expr(matches_query(query: ^arg(:query)))
      prepare build(sort: [search_rank: {%{query: arg(:query)}, :desc}])
    end

    create :upsert do
      description "Upserts an attack pattern parsed from the CAPEC XML catalog."

      accept [
        :capec_id,
        :name,
        :abstraction,
        :status,
        :description,
        :extended_description,
        :likelihood_of_attack,
        :typical_severity,
        :prerequisites,
        :mitigations,
        :consequences
      ]

      upsert? true

      upsert_fields [
        :name,
        :abstraction,
        :status,
        :description,
        :extended_description,
        :likelihood_of_attack,
        :typical_severity,
        :prerequisites,
        :mitigations,
        :consequences,
        :updated_at
      ]
    end

    action :sync_capec_catalog, OkResult do
      description """
      Downloads the CAPEC XML catalog from MITRE, checks Last-Modified to skip
      re-processing if unchanged, parses, and bulk-upserts all attack patterns.
      """

      run CatalogSync
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if always()
    end
  end

  attributes do
    attribute :capec_id, :integer do
      primary_key? true
      allow_nil? false
      writable? true
      public? true
      description "The numeric CAPEC identifier (e.g. 66 for CAPEC-66)."
    end

    attribute :name, :string do
      allow_nil? false
      public? true
    end

    attribute :abstraction, Varsel.CAPEC.AttackPattern.Abstraction do
      allow_nil? false
      public? true
    end

    attribute :status, Varsel.CAPEC.AttackPattern.Status do
      allow_nil? false
      public? true
    end

    attribute :description, :string do
      allow_nil? true
      public? true
    end

    attribute :extended_description, :string do
      allow_nil? true
      public? true
    end

    attribute :likelihood_of_attack, Varsel.CAPEC.AttackPattern.Likelihood do
      allow_nil? true
      public? true
    end

    attribute :typical_severity, Varsel.CAPEC.AttackPattern.Severity do
      allow_nil? true
      public? true
    end

    attribute :prerequisites, :string do
      allow_nil? true
      public? true
      description "Concatenated plain-text prerequisites for this attack pattern."
    end

    attribute :mitigations, :string do
      allow_nil? true
      public? true
      description "Concatenated plain-text description of mitigations."
    end

    attribute :consequences, :string do
      allow_nil? true
      public? true
      description "Concatenated plain-text description of scopes and impacts."
    end

    timestamps()
  end

  relationships do
    many_to_many :weaknesses, Weakness do
      through AttackPatternWeakness
      source_attribute :capec_id
      source_attribute_on_join_resource :capec_id
      destination_attribute :cwe_id
      destination_attribute_on_join_resource :cwe_id
      public? true
    end

    has_many :related_attack_pattern_relationships, AttackPatternRelationship do
      source_attribute :capec_id
      destination_attribute :source_capec_id
      public? true
    end
  end

  calculations do
    # websearch_to_tsquery (not plainto_): tolerates arbitrary user input
    # without raising, and honors OR / quoted-phrase operators the caller may
    # pass for broader recall.
    calculate :matches_query,
              :boolean,
              expr(fragment("search_vector @@ websearch_to_tsquery('english', ?)", ^arg(:query))) do
      public? false

      argument :query, :string do
        allow_nil? false
      end
    end

    calculate :search_rank,
              :float,
              expr(
                fragment(
                  "ts_rank(search_vector, websearch_to_tsquery('english', ?))",
                  ^arg(:query)
                )
              ) do
      public? false

      argument :query, :string do
        allow_nil? false
      end
    end
  end
end
