# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CommentTest do
  use Varsel.DataCase, async: false

  alias Ash.Resource.Info
  alias Varsel.Cases
  alias Varsel.Cases.Comment
  alias Varsel.Fixtures

  setup do
    poc = Fixtures.register_user("comment_poc", :poc)
    %{poc: poc, case: Fixtures.open_case(poc)}
  end

  test "posts a comment on a case", %{poc: poc, case: case_record} do
    comment =
      Cases.post_case_comment!(%{case_id: case_record.id, body: "Looks incomplete."}, actor: poc)

    assert comment.author_id == poc.id
    assert [%{body: "Looks incomplete."}] = Cases.list_case_comments!(case_record.id, actor: poc)
  end

  test "optionally references a proposal of the same case", %{poc: poc, case: case_record} do
    proposal =
      Cases.create_case_proposal!(
        %{
          case_id: case_record.id,
          target: :case,
          operation: :set,
          field_name: "title",
          proposed_value: %{"value" => "x"}
        },
        actor: poc
      )

    comment =
      Cases.post_case_comment!(
        %{case_id: case_record.id, proposal_id: proposal.id, body: "Why this title?"},
        actor: poc
      )

    assert comment.proposal_id == proposal.id
  end

  test "rejects a proposal reference from another case", %{poc: poc, case: case_record} do
    other_case = Fixtures.open_case(poc, %{title: "Other"})

    proposal =
      Cases.create_case_proposal!(
        %{
          case_id: other_case.id,
          target: :case,
          operation: :set,
          field_name: "title",
          proposed_value: %{"value" => "x"}
        },
        actor: poc
      )

    assert {:error, error} =
             Cases.post_case_comment(
               %{case_id: case_record.id, proposal_id: proposal.id, body: "cross-case"},
               actor: poc
             )

    assert Exception.message(error) =~ "different case"
  end

  test "commenting stays possible on a closed case", %{poc: poc, case: case_record} do
    Cases.close_case!(case_record, %{}, actor: poc)

    assert %Comment{} =
             Cases.post_case_comment!(%{case_id: case_record.id, body: "post-mortem"}, actor: poc)
  end

  test "comments are append-only: no update or destroy actions exist" do
    action_names = Comment |> Info.actions() |> Enum.map(& &1.type)

    refute :update in action_names
    refute :destroy in action_names
  end

  test "an unassigned supporter can neither read nor post", %{case: case_record} do
    supporter = Fixtures.register_user("comment_supporter", :supporter)

    assert {:error, %Ash.Error.Forbidden{}} =
             Cases.post_case_comment(%{case_id: case_record.id, body: "hi"}, actor: supporter)

    assert [] = Cases.list_case_comments!(case_record.id, actor: supporter)
  end
end
