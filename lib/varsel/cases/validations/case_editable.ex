# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Validations.CaseEditable do
  @moduledoc """
  Content-freeze rule: case data may only change while the case is in
  `:draft` or `:review`. Anything later (`:approved` onward) requires
  reopening the case first.

  Used by `Varsel.Cases.Case` itself and by every child resource (which
  loads the parent case through its denormalized `case_id`).
  """

  use Ash.Resource.Validation

  alias Varsel.Cases.Case

  @editable_states [:draft, :review]

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    case fetch_state(changeset) do
      {:ok, state} when state in @editable_states ->
        :ok

      {:ok, state} ->
        {:error,
         field: :state,
         message: "case content is frozen in the %{state} state; reopen the case to edit it",
         vars: [state: state]}

      :error ->
        {:error, field: :case_id, message: "case does not exist"}
    end
  end

  defp fetch_state(%Ash.Changeset{resource: Case} = changeset), do: {:ok, changeset.data.state}

  defp fetch_state(%Ash.Changeset{action_type: :create} = changeset) do
    changeset
    |> Ash.Changeset.get_attribute(:case_id)
    |> case_state()
  end

  defp fetch_state(%Ash.Changeset{} = changeset), do: case_state(changeset.data.case_id)

  defp case_state(nil), do: :error

  defp case_state(case_id) do
    case Varsel.Cases.get_case(case_id, authorize?: false, not_found_error?: false) do
      {:ok, %{state: state}} -> {:ok, state}
      {:ok, nil} -> :error
      {:error, _} -> :error
    end
  end
end
