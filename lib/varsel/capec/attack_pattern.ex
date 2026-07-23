# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.AttackPattern.OkResult do
  @moduledoc false
  use Ash.Type.Enum, values: [:ok]
end

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

  alias Varsel.CAPEC.AttackPattern.OkResult
  alias Varsel.CAPEC.AttackPatternRelationship
  alias Varsel.CAPEC.AttackPatternWeakness
  alias Varsel.CAPEC.CapecMetadata
  alias Varsel.CAPEC.CapecXmlParser

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

  @catalog_url "https://capec.mitre.org/data/xml/capec_latest.xml"

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

    read :get_by_capec_id do
      description "Fetches a single attack pattern by its integer CAPEC ID."
      argument :capec_id, :integer, allow_nil?: false
      get? true
      filter expr(capec_id == ^arg(:capec_id))
    end

    read :search do
      description "Full-text search over name, description, prerequisites, mitigations, and consequences."
      argument :query, :string, allow_nil?: false

      filter expr(matches_query(query: ^arg(:query)))
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

      argument :related_weaknesses, {:array, :integer}, default: []

      argument :related_attack_patterns, {:array, :map}, default: []

      change manage_relationship(:related_weaknesses, :weaknesses,
               on_lookup: :relate,
               on_no_match: :ignore,
               on_match: :ignore,
               on_missing: :unrelate,
               use_identities: [:_primary_key]
             )

      change manage_relationship(:related_attack_patterns, :related_attack_pattern_relationships,
               on_no_match: :create,
               on_match: :ignore,
               on_missing: :unrelate,
               use_identities: [:_primary_key]
             )

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

      run fn _input, context ->
        opts = Varsel.ObanContext.forward(context)

        [_] = Varsel.CWE.read_cwe_metadata!(opts)

        req = build_req()
        stored_last_modified = fetch_stored_last_modified(opts)

        headers =
          if stored_last_modified do
            [{"if-modified-since", stored_last_modified}]
          else
            []
          end

        case Req.get!(req, url: @catalog_url, headers: headers) do
          %{status: 304} ->
            {:ok, :ok}

          %{status: 200, body: body, headers: resp_headers} ->
            body
            |> Varsel.Xml.chunk_binary()
            |> CapecXmlParser.stream()
            |> upsert_all(opts)

            new_last_modified = get_header(resp_headers, "last-modified")
            update_metadata(new_last_modified, opts)
            {:ok, :ok}

          %{status: status} ->
            {:error, "CAPEC catalog download failed with HTTP #{status}"}
        end
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
    many_to_many :weaknesses, Varsel.CWE.Weakness do
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
    calculate :matches_query,
              :boolean,
              expr(fragment("search_vector @@ plainto_tsquery('english', ?)", ^arg(:query))) do
      public? false

      argument :query, :string do
        allow_nil? false
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Private sync helpers (used by the :sync_capec_catalog action run fn)
  # ---------------------------------------------------------------------------

  defp fetch_stored_last_modified(opts) do
    case Varsel.CAPEC.read_capec_metadata(opts) do
      {:ok, [%{last_modified: lm}]} -> lm
      _ -> nil
    end
  end

  defp upsert_all(attack_patterns, opts) do
    {:ok, _} =
      Ash.transact(__MODULE__, fn ->
        attack_patterns
        |> Stream.chunk_every(200)
        |> Enum.each(fn chunk ->
          Varsel.CAPEC.upsert_attack_pattern!(
            chunk,
            Keyword.put(opts, :bulk_options, return_errors?: true, stop_on_error?: true)
          )
        end)
      end)
  end

  defp update_metadata(last_modified, opts) do
    Ash.create!(
      CapecMetadata,
      %{last_modified: last_modified, last_synced_at: DateTime.utc_now()},
      Keyword.put(opts, :action, :upsert)
    )
  end

  @extra_req_opts Keyword.take(
                    Application.compile_env(:varsel, :capec_catalog, []),
                    [:plug]
                  )

  defp build_req do
    Req.new([retry: false] ++ @extra_req_opts)
  end

  defp get_header(headers, name) do
    case Map.fetch(headers, name) do
      {:ok, [value | _]} -> value
      {:ok, value} when is_binary(value) -> value
      :error -> nil
    end
  end
end
