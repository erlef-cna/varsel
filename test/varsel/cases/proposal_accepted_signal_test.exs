# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ProposalAcceptedSignalTest do
  @moduledoc """
  Accepting a proposal sweeps the open proposals it makes obsolete, through
  the `:proposal_accepted` signal. What competes depends on the operation, so
  each one is checked separately.
  """

  use Varsel.DataCase, async: true

  import Varsel.Fixtures

  alias Varsel.Cases
  alias Varsel.Cases.Proposal

  setup do
    poc = register_user("poc", :poc)

    {:ok, poc: poc, case_record: open_case(poc, %{title: "A case"})}
  end

  defp propose_set(actor, case_record, field, value, extra \\ %{}) do
    Cases.create_case_proposal!(
      Map.merge(
        %{
          case_id: case_record.id,
          target: :case,
          operation: :set,
          field_name: field,
          proposed_value: %{"value" => value}
        },
        extra
      ),
      actor: actor
    )
  end

  defp state(proposal), do: Ash.get!(Proposal, proposal.id, authorize?: false).state

  test "a :set sweeps the same field and leaves another alone", %{
    poc: poc,
    case_record: case_record
  } do
    first = propose_set(poc, case_record, "title", "A")
    competing = propose_set(poc, case_record, "title", "B")
    unrelated = propose_set(poc, case_record, "description_md", "Something")

    Cases.accept_case_proposal!(first, %{}, actor: poc)

    assert state(competing) == :superseded
    assert state(unrelated) == :open
  end

  test "a counter-proposal sweeps its parent", %{poc: poc, case_record: case_record} do
    parent = propose_set(poc, case_record, "title", "Parent")
    counter = propose_set(poc, case_record, "title", "Counter", %{parent_proposal_id: parent.id})

    Cases.accept_case_proposal!(counter, %{}, actor: poc)

    assert state(parent) == :superseded
  end

  test "the accepted proposal is not swept with the rest", %{poc: poc, case_record: case_record} do
    first = propose_set(poc, case_record, "title", "A")
    _competing = propose_set(poc, case_record, "title", "B")

    Cases.accept_case_proposal!(first, %{}, actor: poc)

    assert state(first) == :accepted
  end

  test "the swept proposal records why", %{poc: poc, case_record: case_record} do
    first = propose_set(poc, case_record, "title", "A")
    competing = propose_set(poc, case_record, "title", "B")

    Cases.accept_case_proposal!(first, %{}, actor: poc)

    swept = Ash.get!(Proposal, competing.id, authorize?: false)

    assert swept.resolution_note == "a competing proposal was accepted"
  end
end
