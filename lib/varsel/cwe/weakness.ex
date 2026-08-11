# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.Weakness.OkResult do
  @moduledoc false
  use Ash.Type.Enum, values: [:ok]
end

defmodule Varsel.CWE.Weakness do
  @moduledoc """
  Represents a single CWE (Common Weakness Enumeration) entry from the MITRE CWE catalog.

  Data is synced from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip on startup
  and weekly thereafter via the `sync_cwe_catalog` scheduled action.

  ## Full-text search

  The `search_vector` column is a PostgreSQL `tsvector GENERATED ALWAYS AS ... STORED`
  column defined directly in the migration (not as an Ash attribute). It combines:
  - `name` at weight A (highest relevance)
  - `description` at weight B
  - `extended_description`, `potential_mitigations`, `common_consequences` at weight C

  Query it via the `:search` read action.

  ## If-Modified-Since deduplication

  Before downloading, a HEAD request compares the server's `Last-Modified` header
  against the value stored in `CweMetadata`. If unchanged, the download is skipped.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CWE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban, AshGraphql.Resource]

  import Ash.Expr

  alias Varsel.CAPEC.AttackPattern
  alias Varsel.CAPEC.AttackPatternWeakness
  alias Varsel.CWE.CatalogSync
  alias Varsel.CWE.View
  alias Varsel.CWE.ViewMembership
  alias Varsel.CWE.Weakness.OkResult
  alias Varsel.CWE.WeaknessClosure
  alias Varsel.CWE.WeaknessRelationship

  graphql do
    type :weakness
  end

  postgres do
    table "cwe_weaknesses"
    repo Varsel.Repo

    # search_vector is a GENERATED ALWAYS AS tsvector column — read-only, never written.
    calculations_to_sql search_vector: "search_vector"

    custom_statements do
      statement :add_search_vector do
        up """
        ALTER TABLE cwe_weaknesses
        ADD COLUMN search_vector tsvector
        GENERATED ALWAYS AS (
          setweight(to_tsvector('english', coalesce(name, '')), 'A') ||
          setweight(to_tsvector('english', coalesce(description, '')), 'B') ||
          setweight(to_tsvector('english', coalesce(extended_description, '')), 'C') ||
          setweight(to_tsvector('english', coalesce(potential_mitigations, '')), 'C') ||
          setweight(to_tsvector('english', coalesce(common_consequences, '')), 'C')
        ) STORED
        """

        down "ALTER TABLE cwe_weaknesses DROP COLUMN IF EXISTS search_vector"
      end

      statement :add_search_vector_gin_index do
        up "CREATE INDEX cwe_weaknesses_search_vector_gin ON cwe_weaknesses USING GIN (search_vector)"
        down "DROP INDEX IF EXISTS cwe_weaknesses_search_vector_gin"
      end
    end
  end

  oban do
    scheduled_actions do
      schedule :sync_cwe_catalog, "0 5 * * 1",
        action: :sync_cwe_catalog,
        worker_module_name: Varsel.CWE.Weakness.SyncCweCatalogWorker,
        queue: :cwe_sync,
        max_attempts: 3

      schedule :sync_cwe_catalog_on_boot, "@reboot",
        action: :sync_cwe_catalog,
        worker_module_name: Varsel.CWE.Weakness.SyncCweCatalogOnBootWorker,
        queue: :cwe_sync,
        max_attempts: 3
    end
  end

  actions do
    read :read do
      description "Lists weaknesses with keyset pagination."
      primary? true
      pagination keyset?: true, required?: false
    end

    read :search do
      description """
      Full-text search over name, description, mitigations, and consequences,
      best match first. Bare words are ANDed; `OR` widens (e.g. `length OR
      quantity OR mismatch`), `"quoted words"` must appear adjacent, and
      `-word` excludes. Words are stemmed, and no input is a syntax error.
      """

      argument :query, :string, allow_nil?: false

      filter expr(matches_query(query: ^arg(:query)))
      prepare build(sort: [search_rank: {%{query: arg(:query)}, :desc}])
    end

    create :upsert do
      description "Upserts a weakness parsed from the CWE XML catalog."

      # Relationships are synced separately (see `sync_relationships/1`) rather
      # than via manage_relationship: nesting it in a chunked bulk_create
      # mis-assigns target_cwe_id across rows in the same batch.
      accept [
        :cwe_id,
        :name,
        :abstraction,
        :status,
        :description,
        :extended_description,
        :potential_mitigations,
        :common_consequences
      ]

      upsert? true

      upsert_fields [
        :name,
        :abstraction,
        :status,
        :description,
        :extended_description,
        :potential_mitigations,
        :common_consequences,
        :updated_at
      ]
    end

    action :sync_cwe_catalog, OkResult do
      description """
      Downloads the CWE XML catalog ZIP from MITRE, checks Last-Modified to skip
      re-processing if unchanged, unzips, parses, and bulk-upserts all weaknesses,
      views, and their relationships/memberships.
      """

      run fn _input, context ->
        CatalogSync.run(Varsel.ObanContext.forward(context))
      end
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
    attribute :cwe_id, :integer do
      primary_key? true
      allow_nil? false
      writable? true
      public? true
      description "The numeric CWE identifier (e.g. 79 for CWE-79)."
    end

    attribute :name, :string do
      allow_nil? false
      public? true
    end

    attribute :abstraction, Varsel.CWE.Weakness.Abstraction do
      allow_nil? false
      public? true
    end

    attribute :status, Varsel.CWE.Weakness.Status do
      allow_nil? false
      public? true
    end

    attribute :description, :string do
      allow_nil? false
      public? true
    end

    attribute :extended_description, :string do
      allow_nil? true
      public? true
    end

    attribute :potential_mitigations, :string do
      allow_nil? true
      public? true
      description "Concatenated plain-text description of all mitigation phases and strategies."
    end

    attribute :common_consequences, :string do
      allow_nil? true
      public? true
      description "Concatenated plain-text description of scopes and impacts."
    end

    timestamps()
  end

  relationships do
    has_many :related_weakness_relationships, WeaknessRelationship do
      source_attribute :cwe_id
      destination_attribute :source_cwe_id
      public? true
    end

    # Reverse of AttackPattern.weaknesses: the CAPEC attack patterns that can
    # exploit this weakness, through the shared join. Lets callers go CWE -> CAPEC
    # (e.g. after picking a CWE, find the attack patterns that map to it).
    many_to_many :related_attack_patterns, AttackPattern do
      through AttackPatternWeakness
      source_attribute :cwe_id
      source_attribute_on_join_resource :cwe_id
      destination_attribute :capec_id
      destination_attribute_on_join_resource :capec_id
      public? true
    end

    many_to_many :member_of_views, View do
      through ViewMembership
      source_attribute :cwe_id
      source_attribute_on_join_resource :cwe_id
      destination_attribute :view_id
      destination_attribute_on_join_resource :view_id
      public? true
    end

    # Closure rows rooted at this weakness (parent_cwe_id = this cwe_id),
    # excluding the self-pair — i.e. every CWE below it in some view's
    # hierarchy. A weakness in more than one view has one subtree per view.
    has_many :child_closure, WeaknessClosure do
      source_attribute :cwe_id
      destination_attribute :parent_cwe_id
      filter expr(descendant_cwe_id != parent_cwe_id)
      public? false
    end

    many_to_many :flat_children, __MODULE__ do
      through WeaknessClosure
      join_relationship :child_closure
      source_attribute :cwe_id
      source_attribute_on_join_resource :parent_cwe_id
      destination_attribute :cwe_id
      destination_attribute_on_join_resource :descendant_cwe_id
      public? true

      description """
      Every weakness below this one in some view's hierarchy, flattened
      across all levels (children, grandchildren, ...) — derived from the
      closure rows rooted at this CWE.
      """
    end

    # Closure rows where this weakness is the descendant (descendant_cwe_id
    # = this cwe_id), excluding the self-pair and the NULL-parent view-root
    # rows (NULL is not a weakness) — i.e. every CWE above it in some view's
    # hierarchy.
    has_many :parent_closure, WeaknessClosure do
      source_attribute :cwe_id
      destination_attribute :descendant_cwe_id
      filter expr(not is_nil(parent_cwe_id) and parent_cwe_id != descendant_cwe_id)
      public? false
    end

    many_to_many :flat_parents, __MODULE__ do
      through WeaknessClosure
      join_relationship :parent_closure
      source_attribute :cwe_id
      source_attribute_on_join_resource :descendant_cwe_id
      destination_attribute :cwe_id
      destination_attribute_on_join_resource :parent_cwe_id
      public? true

      description """
      Every weakness above this one in some view's hierarchy, flattened
      across all levels (parent, grandparent, ...) — derived from the
      closure rows where this CWE is the descendant.
      """
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
