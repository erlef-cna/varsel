# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment.Validations.ProposalBelongsToCase do
  @moduledoc """
  A comment referencing a proposal must reference a proposal of its own case.
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    proposal_id = Ash.Changeset.get_attribute(changeset, :proposal_id)
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)

    with false <- is_nil(proposal_id),
         {:ok, %{case_id: proposal_case_id}} <-
           Varsel.Cases.get_case_proposal(proposal_id, authorize?: false),
         false <- proposal_case_id == case_id do
      {:error, field: :proposal_id, message: "belongs to a different case"}
    else
      true -> :ok
      {:error, _} -> {:error, field: :proposal_id, message: "does not exist"}
    end
  end
end
