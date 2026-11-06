# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CommentReactionTest do
  use Varsel.DataCase, async: true

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Cases.CommentReaction
  alias Varsel.Fixtures

  setup do
    poc = Fixtures.register_user("reaction_poc", :poc)
    case_record = Fixtures.open_case(poc)
    comment = Cases.post_case_comment!(%{case_id: case_record.id, body: "Patched?"}, actor: poc)

    %{poc: poc, case: case_record, comment: comment}
  end

  defp react(case_record, comment, emoji, actor) do
    Cases.react_to_case_comment(%{case_id: case_record.id, comment_id: comment.id, emoji: emoji},
      actor: actor
    )
  end

  test "an assigned user reacts, and reacting twice with one emoji keeps one reaction", %{
    poc: poc,
    case: case_record,
    comment: comment
  } do
    assigned = Fixtures.register_user("reaction_assigned")
    Cases.assign_case_user!(%{case_id: case_record.id, user_id: assigned.id}, actor: poc)

    assert {:ok, %CommentReaction{user_id: user_id}} =
             react(case_record, comment, :rocket, assigned)

    assert user_id == assigned.id
    assert {:ok, _again} = react(case_record, comment, :rocket, assigned)
    assert {:ok, _other} = react(case_record, comment, :eyes, assigned)

    assert [:eyes, :rocket] =
             CommentReaction
             |> Ash.read!(authorize?: false)
             |> Enum.map(& &1.emoji)
             |> Enum.sort()
  end

  test "a reaction names the case of its comment", %{poc: poc, case: case_record} do
    other_case = Fixtures.open_case(poc, %{title: "Other"})
    other = Cases.post_case_comment!(%{case_id: other_case.id, body: "x"}, actor: poc)

    assert {:error, %Invalid{}} = react(case_record, other, :heart, poc)
  end

  test "an unassigned supporter can neither react nor see reactions", %{
    poc: poc,
    case: case_record,
    comment: comment
  } do
    supporter = Fixtures.register_user("reaction_supporter", :supporter)
    {:ok, _reaction} = react(case_record, comment, :heart, poc)

    # The comment is one they cannot read, so it does not exist for them.
    assert {:error, %Invalid{}} = react(case_record, comment, :rocket, supporter)
    assert [] = Cases.list_case_comment_reactions!(actor: supporter)
    assert [%{emoji: :heart}] = Cases.list_case_comment_reactions!(actor: poc)
  end

  test "an anonymous reaction is refused", %{case: case_record, comment: comment} do
    assert {:error, _refused} = react(case_record, comment, :heart, nil)
    refute Ash.can?({CommentReaction, :react}, nil)
    assert [] = Ash.read!(CommentReaction, authorize?: false)
  end

  test "an anonymous read is refused, not empty", %{poc: poc, case: case_record, comment: comment} do
    {:ok, _reaction} = react(case_record, comment, :heart, poc)

    assert {:error, %Forbidden{}} = Cases.list_case_comment_reactions(actor: nil)
    refute Ash.can?({CommentReaction, :read}, nil)
  end

  test "only the person who reacted takes it back", %{
    poc: poc,
    case: case_record,
    comment: comment
  } do
    other_poc = Fixtures.register_user("reaction_other_poc", :poc)
    {:ok, reaction} = react(case_record, comment, :laugh, poc)

    assert {:error, %Forbidden{}} =
             Cases.take_back_case_comment_reaction(reaction, actor: other_poc)

    assert :ok = Cases.take_back_case_comment_reaction(reaction, actor: poc)
    assert [] = Ash.read!(CommentReaction, authorize?: false)
  end
end
