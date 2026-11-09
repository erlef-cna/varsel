# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CommentReactionTest do
  use Varsel.DataCase, async: true

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.Cases.CommentReaction
  alias Varsel.Fixtures

  setup do
    poc = Fixtures.register_user("reaction_poc", :poc)
    case_record = Fixtures.open_case(poc)
    comment = Cases.post_case_comment!(%{case_id: case_record.id, body: "Patched?"}, actor: poc)

    %{poc: poc, case: case_record, comment: comment}
  end

  defp react(comment, emoji, actor) do
    Cases.react_to_case_comment(%{comment_id: comment.id, emoji: emoji}, actor: actor)
  end

  test "an assigned user reacts, and reacting twice with one emoji keeps one reaction", %{
    poc: poc,
    case: case_record,
    comment: comment
  } do
    assigned = Fixtures.register_user("reaction_assigned")
    Cases.assign_case_user!(%{case_id: case_record.id, user_id: assigned.id}, actor: poc)

    assert {:ok, %CommentReaction{user_id: user_id}} =
             react(comment, :rocket, assigned)

    assert user_id == assigned.id
    assert {:ok, _again} = react(comment, :rocket, assigned)
    assert {:ok, _other} = react(comment, :eyes, assigned)

    assert [:eyes, :rocket] =
             CommentReaction
             |> Ash.read!(authorize?: false)
             |> Enum.map(& &1.emoji)
             |> Enum.sort()
  end

  test "a reaction belongs to the case of its comment", %{poc: poc, case: case_record} do
    other_case = Fixtures.open_case(poc, %{title: "Other"})
    other = Cases.post_case_comment!(%{case_id: other_case.id, body: "x"}, actor: poc)

    {:ok, reaction} = react(other, :heart, poc)
    reaction = Ash.load!(reaction, [:case_id, :case], actor: poc)

    assert reaction.case_id == other_case.id
    assert reaction.case.id == other_case.id
    refute reaction.case_id == case_record.id
  end

  test "an unassigned supporter can neither react nor see reactions", %{
    poc: poc,
    comment: comment
  } do
    supporter = Fixtures.register_user("reaction_supporter", :supporter)
    {:ok, _reaction} = react(comment, :heart, poc)

    assert {:error, %Forbidden{}} = react(comment, :rocket, supporter)
    assert [] = Cases.list_case_comment_reactions!(actor: supporter)
    assert [%{emoji: :heart}] = Cases.list_case_comment_reactions!(actor: poc)
  end

  test "an anonymous reaction is refused", %{comment: comment} do
    assert {:error, _refused} = react(comment, :heart, nil)
    refute Ash.can?({CommentReaction, :react}, nil)
    assert [] = Ash.read!(CommentReaction, authorize?: false)
  end

  test "an anonymous read is refused, not empty", %{poc: poc, comment: comment} do
    {:ok, _reaction} = react(comment, :heart, poc)

    assert {:error, %Forbidden{}} = Cases.list_case_comment_reactions(actor: nil)
    refute Ash.can?({CommentReaction, :read}, nil)
  end

  test "only the person who reacted takes it back", %{poc: poc, comment: comment} do
    other_poc = Fixtures.register_user("reaction_other_poc", :poc)
    {:ok, reaction} = react(comment, :laugh, poc)

    assert {:error, %Forbidden{}} =
             Cases.take_back_case_comment_reaction(reaction, actor: other_poc)

    assert :ok = Cases.take_back_case_comment_reaction(reaction, actor: poc)
    assert [] = Ash.read!(CommentReaction, authorize?: false)
  end
end
