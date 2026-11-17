# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Actions.RecheckPublishedDrift do
  @moduledoc """
  Queues a drift check of every published case, whenever its last one ran.

  Implements `Varsel.Cases.Case`'s `:recheck_published_drift` action.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.Cases.Case

  require Ash.Query

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    opts = Ash.Context.to_opts(context, bulk_options: [strategy: :stream, return_errors?: true])

    Case
    |> Ash.Query.filter(state == :published)
    |> Varsel.Cases.recheck_case_drift(opts)
    |> case do
      %Ash.BulkResult{status: :success} -> {:ok, :ok}
      %Ash.BulkResult{errors: errors} -> {:error, errors}
    end
  end
end
