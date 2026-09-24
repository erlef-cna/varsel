# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.WeaknessClosure.Actions.Refresh do
  @moduledoc """
  Rebuilds the `cwe_weakness_closure` materialized view.
  """

  use Ash.Resource.Actions.Implementation

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, _context) do
    # Keeps reads of the view unblocked while it rebuilds; requires the
    # unique index created in the migration.
    Varsel.Repo.query!("REFRESH MATERIALIZED VIEW CONCURRENTLY cwe_weakness_closure")
    {:ok, :ok}
  end
end
