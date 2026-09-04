# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseAssignmentTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.Cases.CaseAssignment
  alias Varsel.Fixtures

  describe ":assign" do
    setup do
      poc = Fixtures.register_user("assign_poc", :poc)
      supporter = Fixtures.register_user("assign_supporter", :supporter)

      %{poc: poc, supporter: supporter, case: Fixtures.open_case(poc)}
    end

    test "a user who has access keeps the assignment they have", %{
      poc: poc,
      supporter: supporter,
      case: case_record
    } do
      attrs = %{case_id: case_record.id, user_id: supporter.id}

      first = Cases.assign_case_user!(Map.put(attrs, :note, "first"), actor: poc)
      repeat = Cases.assign_case_user!(Map.put(attrs, :note, "second"), actor: poc)

      assert repeat.id == first.id
      assert repeat.note == "first"

      assert [%{id: id}] =
               Cases.list_case_assignments!(
                 query: [filter: [case_id: case_record.id, user_id: supporter.id]],
                 actor: poc
               )

      assert id == first.id
    end

    test "a repeat assignment writes no version", %{
      poc: poc,
      supporter: supporter,
      case: case_record
    } do
      attrs = %{case_id: case_record.id, user_id: supporter.id}

      assignment = Cases.assign_case_user!(attrs, actor: poc)
      Cases.assign_case_user!(attrs, actor: poc)

      versions =
        CaseAssignment.Version
        |> Ash.read!(authorize?: false)
        |> Enum.filter(&(&1.version_source_id == assignment.id))

      assert length(versions) == 1
    end
  end
end
