# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Actions.PublishedCweSubtreeCounts do
  @moduledoc """
  Counts published CVE records reachable (recursively) under each of a set of
  CWE ids, scoped to one view.

  One query against `cwe_weakness_closure`: every published record's CWE ids
  are unnested and joined to the closure rows for `view_id`, keeping only
  rows whose `parent_cwe_id` is one of the requested `cwe_ids`, then grouped
  by that parent. `count(DISTINCT r.id)` because a single CVE can reach the
  same parent through more than one of its own CWE ids or via more than one
  descendant path. A parent with zero matching CVEs has no group and simply
  does not appear in the result — the caller fills in the zero.
  """

  use Ash.Resource.Actions.Implementation

  import Ecto.Query

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    opts = Ash.Context.to_opts(context)
    view_id = input.arguments.view_id
    cwe_ids = input.arguments.cwe_ids

    with {:ok, ecto_query} <-
           opts
           |> Varsel.CVE.query_to_list_published_cve_records()
           |> Ash.Query.data_layer_query() do
      {:ok, count_by_parent(ecto_query, view_id, cwe_ids)}
    end
  end

  defp count_by_parent(ecto_query, view_id, cwe_ids) do
    ecto_query
    |> exclude(:select)
    |> exclude(:order_by)
    |> join(
      :inner_lateral,
      [r],
      cwe in fragment("SELECT unnest(cve_record_cwe_ids(?)) AS id", r.cve_json),
      on: true
    )
    |> join(
      :inner,
      [r, cwe],
      c in Varsel.CWE.WeaknessClosure,
      on:
        c.descendant_cwe_id == cwe.id and c.view_id == ^view_id and
          c.parent_cwe_id in ^cwe_ids
    )
    |> group_by([r, cwe, c], c.parent_cwe_id)
    |> select([r, cwe, c], {c.parent_cwe_id, count(r.id, :distinct)})
    |> Varsel.Repo.all()
  end
end
