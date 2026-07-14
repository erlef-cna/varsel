# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CWE.Weakness.OkResult do
  @moduledoc false
  use Ash.Type.Enum, values: [:ok]
end

defmodule CveManagement.CWE.Weakness do
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
    otp_app: :cve_management,
    domain: CveManagement.CWE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban, AshGraphql.Resource]

  import Ash.Expr

  alias CveManagement.CWE.CweMetadata
  alias CveManagement.CWE.CweXmlParser
  alias CveManagement.CWE.Weakness.OkResult
  alias CveManagement.CWE.WeaknessRelationship

  graphql do
    type :weakness
  end

  postgres do
    table "cwe_weaknesses"
    repo CveManagement.Repo

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

  @catalog_url "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

  oban do
    scheduled_actions do
      schedule :sync_cwe_catalog, "0 5 * * 1",
        action: :sync_cwe_catalog,
        worker_module_name: CveManagement.CWE.Weakness.SyncCweCatalogWorker,
        queue: :cwe_sync,
        max_attempts: 3

      schedule :sync_cwe_catalog_on_boot, "@reboot",
        action: :sync_cwe_catalog,
        worker_module_name: CveManagement.CWE.Weakness.SyncCweCatalogOnBootWorker,
        queue: :cwe_sync,
        max_attempts: 3
    end
  end

  actions do
    read :read do
      primary? true
      pagination keyset?: true, required?: false
    end

    read :get_by_cwe_id do
      description "Fetches a single weakness by its integer CWE ID."
      argument :cwe_id, :integer, allow_nil?: false
      get? true
      filter expr(cwe_id == ^arg(:cwe_id))
    end

    read :search do
      description "Full-text search over name, description, mitigations, and consequences."
      argument :query, :string, allow_nil?: false

      filter expr(matches_query(query: ^arg(:query)))
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
      re-processing if unchanged, unzips, parses, and bulk-upserts all weaknesses.
      """

      run fn _input, _context ->
        req = build_req()
        stored_last_modified = fetch_stored_last_modified()

        headers =
          if stored_last_modified do
            [{"if-modified-since", stored_last_modified}]
          else
            []
          end

        case Req.get(req, url: @catalog_url, headers: headers) do
          {:ok, %{status: 304}} ->
            {:ok, :ok}

          {:ok, %{status: 200, body: body, headers: resp_headers}} ->
            {:ok, xml} = extract_xml(body)
            weaknesses = CweXmlParser.parse!(xml)
            upsert_all(weaknesses)
            new_last_modified = get_header(resp_headers, "last-modified")
            update_metadata(new_last_modified)
            {:ok, :ok}

          {:ok, %{status: status}} ->
            {:error, "CWE catalog download failed with HTTP #{status}"}

          {:error, exception} ->
            {:error, "CWE catalog download failed: #{Exception.message(exception)}"}
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

    attribute :abstraction, CveManagement.CWE.Weakness.Abstraction do
      allow_nil? false
      public? true
    end

    attribute :status, CveManagement.CWE.Weakness.Status do
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
  # Private sync helpers (used by the :sync_cwe_catalog action run fn)
  # ---------------------------------------------------------------------------

  defp fetch_stored_last_modified do
    case Ash.read(CweMetadata, authorize?: false) do
      {:ok, [%{last_modified: lm}]} -> lm
      _ -> nil
    end
  end

  # Req automatically unzips zip responses into a list of {filename, content} tuples.
  # Handle both that case and a raw binary (e.g. in production with a real HTTP response).
  defp extract_xml(files) when is_list(files) do
    case Enum.find(files, fn {name, _} -> String.ends_with?(to_string(name), ".xml") end) do
      {_name, xml} -> {:ok, xml}
      nil -> {:error, "No XML file found in CWE ZIP archive"}
    end
  end

  defp extract_xml(zip_binary) when is_binary(zip_binary) do
    case :zip.unzip(zip_binary, [:memory]) do
      {:ok, files} -> extract_xml(files)
      {:error, reason} -> {:error, "Failed to unzip CWE catalog: #{inspect(reason)}"}
    end
  end

  defp upsert_all(weaknesses) do
    {:ok, _} =
      Ash.transact(__MODULE__, fn ->
        # 1. Upsert the weaknesses themselves (without relationships).
        weaknesses
        |> Stream.chunk_every(200)
        |> Enum.each(fn chunk ->
          chunk
          |> Enum.map(&Map.delete(&1, :related_weaknesses))
          |> Ash.bulk_create!(__MODULE__, :upsert,
            authorize?: false,
            return_errors?: true,
            stop_on_error?: true
          )
        end)

        # 2. Sync relationships as a flat set, now that every target exists.
        sync_relationships(weaknesses)
      end)
  end

  # Rebuilds the relationship table from the parsed catalog. Relationships are
  # inserted flat (with an explicit source_cwe_id) instead of through the
  # weakness upsert's manage_relationship, which mis-maps targets under a
  # chunked bulk_create. Rows referencing an unknown weakness are dropped
  # (the target FK would reject them anyway).
  defp sync_relationships(weaknesses) do
    known = MapSet.new(weaknesses, & &1.cwe_id)

    rows =
      Enum.flat_map(weaknesses, fn %{cwe_id: source_cwe_id} = weakness ->
        weakness
        |> Map.get(:related_weaknesses, [])
        |> Enum.filter(&MapSet.member?(known, &1.target_cwe_id))
        |> Enum.map(&Map.put(&1, :source_cwe_id, source_cwe_id))
      end)

    Ash.bulk_create!(rows, WeaknessRelationship, :create,
      authorize?: false,
      return_errors?: true,
      stop_on_error?: true,
      batch_size: 500
    )

    :ok
  end

  defp update_metadata(last_modified) do
    Ash.create!(CweMetadata, %{last_modified: last_modified, last_synced_at: DateTime.utc_now()},
      action: :upsert,
      authorize?: false
    )
  end

  @extra_req_opts Keyword.take(Application.compile_env(:cve_management, :cwe_catalog, []), [:plug])

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
