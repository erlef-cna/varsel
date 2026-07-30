# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Actions.PublishedQuarterCounts do
  @moduledoc """
  Counts published CVE records per quarter of publication.

  Groups the `:list_published` query in SQL, so the corpus stays in the
  database and one row per quarter comes back.
  """

  use Ash.Resource.Actions.Implementation

  import Ecto.Query

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    opts = Ash.Context.to_opts(context)

    with {:ok, ecto_query} <-
           opts
           |> Varsel.CVE.query_to_list_published_cve_records()
           |> Ash.Query.data_layer_query() do
      {:ok, count_by_quarter(ecto_query)}
    end
  end

  defp count_by_quarter(ecto_query) do
    ecto_query
    |> exclude(:select)
    |> exclude(:order_by)
    |> group_by([r], fragment("cve_record_published_quarter(?)", r.cve_json))
    |> select([r], {fragment("cve_record_published_quarter(?)", r.cve_json), count(r.id)})
    |> Varsel.Repo.all()
    |> Enum.reject(fn {quarter, _count} -> is_nil(quarter) end)
  end
end
