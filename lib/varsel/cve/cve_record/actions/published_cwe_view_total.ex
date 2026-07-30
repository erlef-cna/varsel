# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Actions.PublishedCweViewTotal do
  @moduledoc """
  Counts published CVE records recursively reachable under one subject
  within a view: a single CWE's subtree when `cwe_id` is given, or the
  whole view (its NULL-parent closure rows — the same nil-means-view-root
  convention `has_cwe_recursively` uses) when it is absent.

  One query, same shape as `PublishedCweSubtreeCounts`: every published
  record's CWE ids are unnested and joined to the closure rows for
  `view_id`, `count(DISTINCT r.id)` because a CVE can reach the subject
  through more than one of its own CWE ids or descendant path.
  """

  use Ash.Resource.Actions.Implementation

  import Ecto.Query

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    opts = Ash.Context.to_opts(context)
    view_id = input.arguments.view_id
    cwe_id = input.arguments.cwe_id

    with {:ok, ecto_query} <-
           opts
           |> Varsel.CVE.query_to_list_published_cve_records()
           |> Ash.Query.data_layer_query() do
      {:ok, total(ecto_query, view_id, cwe_id)}
    end
  end

  defp total(ecto_query, view_id, cwe_id) do
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
          fragment(
            "((?::bigint IS NULL AND ? IS NULL) OR ? = ?)",
            type(^cwe_id, :integer),
            c.parent_cwe_id,
            c.parent_cwe_id,
            type(^cwe_id, :integer)
          )
    )
    |> select([r, cwe, c], count(r.id, :distinct))
    |> Varsel.Repo.one()
  end
end
