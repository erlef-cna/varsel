# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.SweepOpenProposals do
  @moduledoc """
  On case close, sweeps every remaining open proposal of the case to
  `:superseded`, so the open-proposal count stays meaningful.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Proposal

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn _changeset, case_record ->
      Proposal
      |> Ash.Query.filter(case_id == ^case_record.id and state == :open)
      |> Varsel.Cases.supersede_case_proposal!(
        %{resolution_note: "the case was closed"},
        actor: context.actor,
        authorize?: false,
        bulk_options: [strategy: :stream, return_errors?: true]
      )

      {:ok, case_record}
    end)
  end
end
