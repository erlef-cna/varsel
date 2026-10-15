# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseClosedSignalTest do
  @moduledoc """
  Closing a case sweeps its open proposals through the `:case_closed` signal.
  The sweep is authorized by the signal, so a role alone is not a way to
  supersede somebody's proposal.
  """

  use Varsel.DataCase, async: true

  import Varsel.Fixtures

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.Cases.Proposal

  setup do
    poc = register_user("poc", :poc)
    case_record = open_case(poc, %{title: "A case"})

    Cases.propose_title!(%{case_id: case_record.id, value: "Better"}, actor: poc)
    [proposal] = Cases.list_open_case_proposals!(case_record.id, actor: poc)

    {:ok, poc: poc, case_record: case_record, proposal: proposal}
  end

  test "the close sweeps every open proposal", %{
    poc: poc,
    case_record: case_record,
    proposal: proposal
  } do
    Cases.close_case!(case_record, %{closed_reason: "not a vuln"}, actor: poc)

    swept = Ash.get!(Proposal, proposal.id, actor: poc)

    assert swept.state == :superseded
    assert swept.resolution_note == "the case was closed"
  end

  test "a direct call still needs the sweep stamp", %{poc: poc, proposal: proposal} do
    assert {:error, %Forbidden{}} =
             Ash.update(proposal, %{}, action: :supersede, actor: poc)
  end

  test "an anonymous caller cannot supersede", %{proposal: proposal} do
    assert {:error, %Forbidden{}} =
             Ash.update(proposal, %{}, action: :supersede, actor: nil)
  end
end
