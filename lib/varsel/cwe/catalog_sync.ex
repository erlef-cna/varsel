# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.CatalogSync do
  @moduledoc """
  Orchestrates a full CWE catalog sync: downloads the MITRE XML catalog,
  parses it, and reconciles weaknesses, views, weakness relationships and
  view memberships against what is currently stored.

  Called from `Varsel.CWE.Weakness`'s `:sync_cwe_catalog` action — kept out of
  that resource module so the resource DSL doesn't keep growing with
  orchestration code.

  ## Write ordering

  Weaknesses and views are catalog entities; relationships and memberships
  are joins that reference them via real foreign keys
  (`cwe_weakness_relationships.view_id -> cwe_views`,
  `cwe_view_memberships.{view_id,cwe_id} -> cwe_views/cwe_weaknesses`). Weaknesses
  and views must be upserted before anything that references them is
  written, so a sync runs in this order inside a single transaction:

    1. upsert weaknesses (collecting relationship facts per chunk)
    2. upsert views (collecting membership facts)
    3. destroy stale views (views MITRE removed from the catalog)
    4. diff-sync weakness relationships
    5. diff-sync view memberships

  Steps 3-5 can run in any order: `cwe_weakness_relationships.view_id` and
  `cwe_view_memberships.view_id` both reference `cwe_views.view_id` with
  `on_delete: :delete`, so destroying a stale view cascades to its own
  relationship/membership rows automatically — these are pure catalog-derived
  join rows with no lifecycle of their own, unlike e.g. a Case's weakness
  link, which must never disappear just because MITRE prunes a CWE.

  Rows referencing an unknown weakness are dropped (their target FK would
  reject them anyway) rather than causing the whole sync to fail —
  Has_Member entries pointing at CWE Categories (not modeled in this app)
  are the expected source of such drops.
  """

  alias Varsel.CWE.CweMetadata
  alias Varsel.CWE.CweXmlParser
  alias Varsel.CWE.View
  alias Varsel.CWE.Weakness

  @catalog_url "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

  @spec run(keyword()) :: {:ok, :ok} | {:error, term()}
  def run(opts) do
    req = build_req()
    stored_last_modified = fetch_stored_last_modified(opts)

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
        sync_catalog(xml, opts)

        new_last_modified = get_header(resp_headers, "last-modified")
        update_metadata(new_last_modified, opts)
        {:ok, :ok}

      {:ok, %{status: status}} ->
        {:error, "CWE catalog download failed with HTTP #{status}"}

      {:error, exception} ->
        {:error, "CWE catalog download failed: #{Exception.message(exception)}"}
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

  defp sync_catalog(xml, opts) do
    {:ok, _} =
      Ash.transact(Weakness, fn ->
        relationship_facts = upsert_weaknesses(xml, opts)
        membership_facts = upsert_views(xml, opts)

        destroy_stale_views(membership_facts, opts)

        sync_relationships(relationship_facts, opts)
        sync_memberships(membership_facts, relationship_facts, opts)
      end)
  end

  # Upserts the weaknesses themselves (without relationships). The weakness
  # stream is single-pass, so keep each chunk's (small) relationship facts
  # for the later diff step.
  defp upsert_weaknesses(xml, opts) do
    xml
    |> Varsel.Xml.chunk_binary()
    |> CweXmlParser.stream_weaknesses()
    |> Stream.chunk_every(200)
    |> Enum.flat_map(fn chunk ->
      chunk
      |> Enum.map(&Map.delete(&1, :related_weaknesses))
      |> Varsel.CWE.upsert_weakness!(Keyword.put(opts, :bulk_options, return_errors?: true, stop_on_error?: true))

      Enum.map(chunk, &Map.take(&1, [:cwe_id, :related_weaknesses]))
    end)
  end

  # Second pass over the same (already in-memory) XML binary. Upserts views
  # and keeps each view's raw member facts for the membership diff step.
  defp upsert_views(xml, opts) do
    xml
    |> Varsel.Xml.chunk_binary()
    |> CweXmlParser.stream_views()
    |> Stream.chunk_every(200)
    |> Enum.flat_map(fn chunk ->
      chunk
      |> Enum.map(&Map.delete(&1, :members))
      |> Varsel.CWE.upsert_view!(Keyword.put(opts, :bulk_options, return_errors?: true, stop_on_error?: true))

      Enum.map(chunk, &Map.take(&1, [:view_id, :members]))
    end)
  end

  # Syncs the relationship table to the parsed catalog as a diff: only rows
  # MITRE added, changed or removed are written — the weekly steady state
  # touches almost nothing. Relationships are inserted flat (with an explicit
  # source_cwe_id) instead of through the weakness upsert's
  # manage_relationship, which mis-maps targets under a chunked bulk_create.
  # Rows referencing an unknown weakness are dropped (the target FK would
  # reject them anyway).
  defp sync_relationships(weaknesses, opts) do
    known = MapSet.new(weaknesses, & &1.cwe_id)

    desired =
      weaknesses
      |> Enum.flat_map(fn %{cwe_id: source_cwe_id} = weakness ->
        weakness
        |> Map.get(:related_weaknesses, [])
        |> Enum.filter(&MapSet.member?(known, &1.target_cwe_id))
        |> Enum.map(&Map.put(&1, :source_cwe_id, source_cwe_id))
      end)
      |> Map.new(&{{&1.source_cwe_id, &1.target_cwe_id, &1.nature, &1.view_id}, &1})

    current =
      Map.new(
        Varsel.CWE.list_weakness_relationships!(opts),
        &{{&1.source_cwe_id, &1.target_cwe_id, &1.nature, &1.view_id}, &1}
      )

    stale = for {key, record} <- current, not Map.has_key?(desired, key), do: record

    to_write =
      for {key, row} <- desired,
          (case current do
             %{^key => record} -> record.ordinal != Map.get(row, :ordinal)
             _absent -> true
           end),
          do: row

    apply_diff(
      stale,
      to_write,
      &Varsel.CWE.create_weakness_relationship!/2,
      %{source: Weakness, name: :related_weakness_relationships},
      opts
    )
  end

  # Syncs view memberships as a diff: desired members are the catalog's
  # Has_Member entries filtered to weaknesses that actually exist (dropping
  # references to CWE Categories, which this app does not model). The join
  # has no payload beyond its composite key, so "changed" never happens —
  # only rows are added or removed.
  defp sync_memberships(views, weaknesses, opts) do
    known = MapSet.new(weaknesses, & &1.cwe_id)

    desired =
      views
      |> Enum.flat_map(fn %{view_id: view_id, members: members} ->
        members
        |> Enum.filter(&MapSet.member?(known, &1))
        |> Enum.map(&{view_id, &1})
      end)
      |> MapSet.new()

    current =
      Map.new(Varsel.CWE.list_view_memberships!(opts), &{{&1.view_id, &1.cwe_id}, &1})

    stale = for {key, record} <- current, not MapSet.member?(desired, key), do: record

    rows =
      for {view_id, cwe_id} <- desired,
          not Map.has_key?(current, {view_id, cwe_id}),
          do: %{view_id: view_id, cwe_id: cwe_id}

    apply_diff(
      stale,
      rows,
      &Varsel.CWE.create_view_membership!/2,
      %{source: View, name: :member_weaknesses},
      opts
    )
  end

  # Views MITRE removed from the catalog. Their relationship/membership rows
  # cascade-delete via the on_delete: :delete foreign keys, so this can run
  # before the relationship/membership diffs below.
  defp destroy_stale_views(views, opts) do
    known = MapSet.new(views, & &1.view_id)

    stale =
      opts
      |> Varsel.CWE.list_views!()
      |> Enum.reject(&MapSet.member?(known, &1.view_id))

    Ash.bulk_destroy!(
      stale,
      :destroy,
      %{},
      Keyword.merge(opts, return_errors?: true, stop_on_error?: true, strategy: :stream)
    )

    :ok
  end

  # The join resources authorize writes by relationship provenance
  # (accessing_from), which manage_relationship would stamp — the flat diff
  # stamps it itself.
  defp apply_diff(stale, rows, create, accessing_from, opts) do
    opts =
      Keyword.update(
        opts,
        :context,
        %{accessing_from: accessing_from},
        &Map.put(&1, :accessing_from, accessing_from)
      )

    Ash.bulk_destroy!(
      stale,
      :destroy,
      %{},
      Keyword.merge(opts, return_errors?: true, stop_on_error?: true, strategy: :stream)
    )

    create.(
      rows,
      Keyword.put(opts, :bulk_options,
        return_errors?: true,
        stop_on_error?: true,
        batch_size: 500
      )
    )

    :ok
  end

  defp fetch_stored_last_modified(opts) do
    case Varsel.CWE.read_cwe_metadata(opts) do
      {:ok, [%{last_modified: lm}]} -> lm
      _ -> nil
    end
  end

  defp update_metadata(last_modified, opts) do
    Ash.create!(
      CweMetadata,
      %{last_modified: last_modified, last_synced_at: DateTime.utc_now()},
      Keyword.put(opts, :action, :upsert)
    )
  end

  @extra_req_opts Keyword.take(Application.compile_env(:varsel, :cwe_catalog, []), [:plug])

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
