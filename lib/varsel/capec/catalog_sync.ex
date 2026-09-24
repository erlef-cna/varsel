# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.CatalogSync do
  @moduledoc """
  Imports the CAPEC attack pattern catalog from MITRE.

  Implements the `:sync_capec_catalog` action of `Varsel.CAPEC.AttackPattern`,
  kept out of that resource so the DSL does not carry orchestration code.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CAPEC.AttackPattern
  alias Varsel.CAPEC.CapecMetadata
  alias Varsel.CAPEC.CapecXmlParser
  alias Varsel.CWE.Weakness

  require Ash.Query

  @catalog_url "https://capec.mitre.org/data/xml/capec_latest.xml"

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
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

  defp fetch_stored_last_modified(opts) do
    case Varsel.CAPEC.read_capec_metadata(opts) do
      {:ok, [%{last_modified: lm}]} -> lm
      _ -> nil
    end
  end

  defp upsert_all(attack_patterns, opts) do
    {:ok, _} =
      Ash.transact(AttackPattern, fn ->
        # 1. Upsert the attack patterns themselves (without relationships) —
        #    nested manage_relationship mis-maps targets under a chunked
        #    bulk_create (see Varsel.CWE.Weakness) and its on_missing
        #    handling never deletes in bulk. The stream is single-pass, so
        #    keep each chunk's relationship facts for the flat sync below.
        facts =
          attack_patterns
          |> Stream.chunk_every(200)
          |> Enum.flat_map(fn chunk ->
            chunk
            |> Enum.map(&Map.drop(&1, [:related_attack_patterns, :related_weaknesses]))
            |> Varsel.CAPEC.upsert_attack_pattern!(
              Keyword.put(opts, :bulk_options, return_errors?: true, stop_on_error?: true)
            )

            Enum.map(
              chunk,
              &Map.take(&1, [:capec_id, :related_attack_patterns, :related_weaknesses])
            )
          end)

        # 2. Sync both join tables as flat diffs, now that every source exists.
        sync_pattern_relationships(facts, opts)
        sync_weakness_joins(facts, opts)
      end)
  end

  # Syncs capec_attack_pattern_relationships to the catalog as a diff — only
  # added and removed edges are written. Targets absent from the catalog are
  # kept, matching the previous manage_relationship behavior.
  defp sync_pattern_relationships(facts, opts) do
    desired =
      MapSet.new(
        for %{capec_id: source} = fact <- facts,
            related <- Map.get(fact, :related_attack_patterns, []),
            do: {source, related.target_capec_id, related.nature}
      )

    current =
      Map.new(
        Varsel.CAPEC.list_attack_pattern_relationships!(opts),
        &{{&1.source_capec_id, &1.target_capec_id, &1.nature}, &1}
      )

    stale = for {key, record} <- current, not MapSet.member?(desired, key), do: record

    rows =
      for {source, target, nature} <- desired,
          not Map.has_key?(current, {source, target, nature}),
          do: %{source_capec_id: source, target_capec_id: target, nature: nature}

    apply_diff(
      stale,
      rows,
      &Varsel.CAPEC.create_attack_pattern_relationship!/2,
      %{source: AttackPattern, name: :related_attack_pattern_relationships},
      opts
    )
  end

  # Syncs the capec→cwe join table as a diff. Only weaknesses present in the
  # local CWE catalog are linked, matching the previous on_lookup: :relate /
  # on_no_match: :ignore behavior.
  defp sync_weakness_joins(facts, opts) do
    referenced =
      for fact <- facts, cwe_id <- Map.get(fact, :related_weaknesses, []), uniq: true, do: cwe_id

    known =
      Weakness
      |> Ash.Query.filter(cwe_id in ^referenced)
      |> Ash.read!(opts)
      |> MapSet.new(& &1.cwe_id)

    desired =
      MapSet.new(
        for %{capec_id: capec_id} = fact <- facts,
            cwe_id <- Map.get(fact, :related_weaknesses, []),
            MapSet.member?(known, cwe_id),
            do: {capec_id, cwe_id}
      )

    current =
      Map.new(
        Varsel.CAPEC.list_attack_pattern_weaknesses!(opts),
        &{{&1.capec_id, &1.cwe_id}, &1}
      )

    stale = for {key, record} <- current, not MapSet.member?(desired, key), do: record

    rows =
      for {capec_id, cwe_id} <- desired,
          not Map.has_key?(current, {capec_id, cwe_id}),
          do: %{capec_id: capec_id, cwe_id: cwe_id}

    apply_diff(
      stale,
      rows,
      &Varsel.CAPEC.create_attack_pattern_weakness!/2,
      %{source: AttackPattern, name: :weaknesses_join_assoc},
      opts
    )
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
