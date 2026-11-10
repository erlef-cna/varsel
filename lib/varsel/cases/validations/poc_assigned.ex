# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Validations.PocAssigned do
  @moduledoc """
  Refuses a case that has no POC assigned to it.

  Review is the assigned POCs' to give, and the `:review_requested`
  notification reaches only them, so a case with none would sit in `:review`
  with nobody told.
  """

  use Ash.Resource.Validation

  alias Ash.Resource.Validation
  alias Varsel.Cases.CaseAssignment

  require Ash.Query

  @impl Validation
  def validate(changeset, _opts, context) do
    case_id = changeset.data.id

    CaseAssignment
    |> Ash.Query.filter(case_id == ^case_id and user.role == :poc)
    |> Ash.exists?(Ash.Context.to_opts(context))
    |> if do
      :ok
    else
      {:error, field: :assignments, message: "needs a POC assigned before it can go to review"}
    end
  end

  @impl Validation
  def atomic(changeset, opts, context), do: validate(changeset, opts, context)
end
