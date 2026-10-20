# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CommentTest do
  use Varsel.DataCase, async: true

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
      Cases.propose_title!(%{case_id: case_record.id, value: "x"}, actor: poc)

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
      Cases.propose_title!(%{case_id: other_case.id, value: "x"}, actor: poc)

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

  # The stream is append-only: a comment's text is never edited here and a
  # comment is never removed. `:claim_for_identity` is the one update, and it
  # writes only who wrote it, never what they wrote.
  test "comments are append-only: nothing may rewrite a body or remove a comment" do
    actions = Info.actions(Comment)

    refute Enum.any?(actions, &(&1.type == :destroy))

    for action <- actions, action.type == :update do
      assert action.name == :claim_for_identity
      assert action.accept == [:author_id]
    end
  end

  test "an unassigned supporter can neither read nor post", %{case: case_record} do
    supporter = Fixtures.register_user("comment_supporter", :supporter)

    assert {:error, %Ash.Error.Forbidden{}} =
             Cases.post_case_comment(%{case_id: case_record.id, body: "hi"}, actor: supporter)

    assert [] = Cases.list_case_comments!(case_record.id, actor: supporter)
  end
end
