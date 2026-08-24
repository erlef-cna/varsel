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

  @stamp %{private: %{proposal_sweep?: true}}

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn _changeset, case_record ->
      opts =
        context
        |> Ash.Context.to_opts()
        |> Keyword.update(:context, @stamp, &Ash.Helpers.deep_merge_maps(&1, @stamp))

      Proposal
      |> Ash.Query.filter(case_id == ^case_record.id and state == :open)
      |> Varsel.Cases.supersede_case_proposal!(
        %{resolution_note: "the case was closed"},
        Keyword.put(opts, :bulk_options, strategy: :stream, return_errors?: true)
      )

      {:ok, case_record}
    end)
  end
end
