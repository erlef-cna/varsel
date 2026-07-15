# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Checks.ActorAssignedToCase do
  @moduledoc """
  Policy check: the actor has a `Varsel.Cases.CaseAssignment` for the case a
  changeset touches.

  Works on create (reads `case_id` from the changeset attributes/arguments),
  update, and destroy (reads it from the record; for `Varsel.Cases.Case`
  itself the record's own `id` is used), and on generic actions (reads the
  `id` argument on `Varsel.Cases.Case`, `case_id` elsewhere). Read actions
  should use the equivalent `expr(exists(...))` filter check instead so
  lists are scoped.
  """

  use Ash.Policy.SimpleCheck

  alias Varsel.Cases.Case

  require Ash.Query

  @impl Ash.Policy.Check
  def describe(_opts), do: "actor is assigned to the case"

  @impl Ash.Policy.SimpleCheck
  def match?(%{id: actor_id}, %{subject: %struct{} = subject}, _opts) when struct in [Ash.Changeset, Ash.ActionInput] do
    case case_id(subject) do
      nil ->
        false

      case_id ->
        Varsel.Cases.CaseAssignment
        |> Ash.Query.filter(case_id == ^case_id and user_id == ^actor_id)
        |> Ash.exists?(authorize?: false)
    end
  end

  def match?(_actor, _context, _opts), do: false

  defp case_id(%Ash.Changeset{resource: Case} = changeset), do: changeset.data.id

  defp case_id(%Ash.Changeset{action_type: :create} = changeset) do
    Ash.Changeset.get_attribute(changeset, :case_id) ||
      changeset.arguments[:case_id]
  end

  defp case_id(%Ash.Changeset{} = changeset), do: changeset.data.case_id

  defp case_id(%Ash.ActionInput{resource: Case} = input), do: input.arguments[:id]
  defp case_id(%Ash.ActionInput{} = input), do: input.arguments[:case_id]
end
