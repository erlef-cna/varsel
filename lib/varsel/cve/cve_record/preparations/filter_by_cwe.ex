# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Preparations.FilterByCwe do
  @moduledoc """
  Applies the optional `cwe_id`/`view_id` filter on `:list_published`.

  With `view_id` present, matches the whole closure subtree (or the whole
  view when `cwe_id` is nil); with only `cwe_id`, matches that CWE directly;
  with neither, the query is untouched.
  """

  use Ash.Resource.Preparation

  require Ash.Query

  @impl Ash.Resource.Preparation
  def prepare(query, _opts, _context) do
    cwe_id = Ash.Query.get_argument(query, :cwe_id)
    view_id = Ash.Query.get_argument(query, :view_id)

    cond do
      view_id != nil ->
        Ash.Query.filter(query, has_cwe_recursively(view_id: ^view_id, cwe_id: ^cwe_id))

      cwe_id != nil ->
        Ash.Query.filter(query, has_cwe(cwe_id: ^cwe_id))

      true ->
        query
    end
  end
end
