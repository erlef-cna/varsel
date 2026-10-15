# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ProposalTargetDestroyedSignalTest do
  @moduledoc """
  Removing a row sweeps the proposals left dangling on it, through the
  `:proposal_target_destroyed` signal. A proposal on another row is
  untouched, and the accepted :delete proposal that drove the removal is
  resolved rather than swept.
  """

  use Varsel.DataCase, async: true

  import Varsel.Fixtures

  alias Varsel.Cases
  alias Varsel.Cases.Proposal

  setup do
    poc = register_user("poc", :poc)
    case_record = open_case(poc, %{title: "A case"})

    {:ok, poc: poc, case_record: case_record, package: add_affected_package(poc, case_record)}
  end

  defp propose_set_on(actor, case_record, target, target_id, field, value) do
    Cases.create_case_proposal!(
      %{
        case_id: case_record.id,
        target: target,
        target_id: target_id,
        operation: :set,
        field_name: field,
        proposed_value: %{"value" => value}
      },
      actor: actor
    )
  end

  defp state(proposal), do: Ash.get!(Proposal, proposal.id, authorize?: false).state

  test "removing a row sweeps the proposals on it", %{
    poc: poc,
    case_record: case_record,
    package: package
  } do
    orphaned =
      propose_set_on(poc, case_record, :affected_package, package.id, "product", "renamed_lib")

    on_the_case = Cases.propose_title!(%{case_id: case_record.id, value: "Better"}, actor: poc)

    Cases.remove_affected_package!(package, actor: poc)

    assert state(orphaned) == :superseded
    assert state(on_the_case) == :open
  end

  test "the swept proposal records why", %{poc: poc, case_record: case_record, package: package} do
    orphaned =
      propose_set_on(poc, case_record, :affected_package, package.id, "product", "renamed_lib")

    Cases.remove_affected_package!(package, actor: poc)

    swept = Ash.get!(Proposal, orphaned.id, authorize?: false)

    assert swept.resolution_note == "the targeted row was deleted"
  end

  test "an accepted :delete is resolved, not swept", %{
    poc: poc,
    case_record: case_record,
    package: package
  } do
    deletion =
      Cases.create_case_proposal!(
        %{
          case_id: case_record.id,
          target: :affected_package,
          target_id: package.id,
          operation: :delete
        },
        actor: poc
      )

    Cases.accept_case_proposal!(deletion, %{}, actor: poc)

    assert state(deletion) == :accepted
  end
end
