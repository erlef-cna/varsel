# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Predisclosure.PredisclosureListTest do
  use Varsel.DataCase, async: true

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Notifications.Notification
  alias Varsel.Predisclosure
  alias Varsel.Predisclosure.PredisclosureList

  require Ash.Query

  setup do
    %{
      poc: Fixtures.register_user("list_poc", :poc),
      supporter: Fixtures.register_user("list_supporter", :supporter),
      subscriber: Fixtures.register_user("list_subscriber"),
      outsider: Fixtures.register_user("list_outsider")
    }
  end

  defp drain, do: Oban.drain_queue(queue: :default, with_recursion: true)

  defp shared_notifications(user) do
    Notification
    |> Ash.Query.filter(user_id == ^user.id and kind == :case_shared)
    |> Ash.read!(authorize?: false)
  end

  defp list(poc, name \\ "Hex.pm maintainers"), do: Predisclosure.create_predisclosure_list!(name, actor: poc)

  describe "managing lists" do
    test "a POC creates, renames and deletes a list", %{poc: poc} do
      list = list(poc)
      list = Predisclosure.rename_predisclosure_list!(list, "Distributors", actor: poc)

      assert list.name == "Distributors"
      assert :ok = Predisclosure.destroy_predisclosure_list!(list, actor: poc)
    end

    test "nobody else manages lists", %{poc: poc, supporter: supporter, subscriber: subscriber} do
      for actor <- [supporter, subscriber, nil] do
        assert {:error, %Forbidden{}} =
                 Predisclosure.create_predisclosure_list("Mine", actor: actor)
      end

      list = list(poc)

      assert {:error, %Forbidden{}} =
               Predisclosure.rename_predisclosure_list(list, "Other", actor: supporter)

      assert {:error, %Forbidden{}} =
               Predisclosure.subscribe_to_predisclosure_list(list.id, subscriber.id, actor: supporter)
    end

    test "only a POC sees lists, subscriptions and the cases on them", %{
      poc: poc,
      subscriber: subscriber
    } do
      list = list(poc)
      Predisclosure.subscribe_to_predisclosure_list!(list.id, subscriber.id, actor: poc)
      case_record = Fixtures.open_case(poc)
      Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)

      assert [_list] = Predisclosure.list_predisclosure_lists!(actor: poc)
      assert [_subscriber] = Predisclosure.list_predisclosure_list_subscribers!(actor: poc)
      assert [_member] = Predisclosure.list_predisclosure_list_members!(actor: poc)

      for actor <- [subscriber, nil] do
        assert {:error, %Forbidden{}} = Predisclosure.list_predisclosure_lists(actor: actor)

        assert {:error, %Forbidden{}} =
                 Predisclosure.list_predisclosure_list_subscribers(actor: actor)

        assert {:error, %Forbidden{}} =
                 Predisclosure.list_predisclosure_list_members(actor: actor)
      end

      assert {:ok, _read} = Cases.get_case(case_record.id, actor: subscriber)
    end
  end

  describe "sharing a case" do
    setup %{poc: poc, subscriber: subscriber} do
      list = list(poc)
      Predisclosure.subscribe_to_predisclosure_list!(list.id, subscriber.id, actor: poc)
      %{list: list, case: Fixtures.open_case(poc, %{title: "Shared case"})}
    end

    test "only a POC shares a case with a list", %{
      case: case_record,
      list: list,
      supporter: supporter,
      poc: poc
    } do
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      assert {:error, %Forbidden{}} =
               Cases.set_case_predisclosure_lists(case_record, [list.id], actor: supporter)

      assert {:ok, _case} = Cases.set_case_predisclosure_lists(case_record, [list.id], actor: poc)
    end

    test "a subscriber reads, comments and proposes, but does not edit", %{
      case: case_record,
      list: list,
      poc: poc,
      subscriber: subscriber
    } do
      assert {:error, _not_found} = Cases.get_case(case_record.id, actor: subscriber)

      Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)

      assert {:ok, read} = Cases.get_case(case_record.id, actor: subscriber)

      assert {:ok, _comment} =
               Cases.post_case_comment(%{case_id: read.id, body: "Thanks."}, actor: subscriber)

      assert {:ok, _proposal} =
               Cases.propose_title(%{case_id: read.id, value: "Better title"}, actor: subscriber)

      assert {:error, %Forbidden{}} =
               Cases.edit_case(read, %{title: "Mine now"}, actor: subscriber)
    end

    test "a supporter on a list does not edit a case they are not assigned to", %{
      case: case_record,
      list: list,
      poc: poc,
      supporter: supporter
    } do
      Predisclosure.subscribe_to_predisclosure_list!(list.id, supporter.id, actor: poc)
      Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)

      read = Cases.get_case!(case_record.id, actor: supporter)

      assert {:error, %Forbidden{}} =
               Cases.edit_case(read, %{title: "Mine now"}, actor: supporter)
    end

    test "someone on no list holding the case does not see it", %{
      case: case_record,
      list: list,
      poc: poc,
      outsider: outsider
    } do
      Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)

      assert {:error, _not_found} = Cases.get_case(case_record.id, actor: outsider)
    end

    test "taking the case off the list or the user off the list ends the access", %{
      case: case_record,
      list: list,
      poc: poc,
      subscriber: subscriber
    } do
      case_record = Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)
      Cases.set_case_predisclosure_lists!(case_record, [], actor: poc)
      assert {:error, _not_found} = Cases.get_case(case_record.id, actor: subscriber)

      case_record = Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)
      assert {:ok, _read} = Cases.get_case(case_record.id, actor: subscriber)

      [subscription] =
        list
        |> Ash.load!(:subscribers, actor: poc)
        |> Map.fetch!(:subscribers)

      Predisclosure.unsubscribe_from_predisclosure_list!(subscription, actor: poc)
      assert {:error, _not_found} = Cases.get_case(case_record.id, actor: subscriber)
    end

    test "a case goes on several lists at once, and setting them again drops the rest", %{
      case: case_record,
      list: list,
      poc: poc,
      subscriber: subscriber,
      outsider: outsider
    } do
      other = Predisclosure.create_predisclosure_list!("Other list", actor: poc)
      Predisclosure.subscribe_to_predisclosure_list!(other.id, outsider.id, actor: poc)

      case_record =
        Cases.set_case_predisclosure_lists!(case_record, [list.id, other.id], actor: poc)

      assert {:ok, _read} = Cases.get_case(case_record.id, actor: subscriber)
      assert {:ok, _read} = Cases.get_case(case_record.id, actor: outsider)

      Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)
      assert {:ok, _read} = Cases.get_case(case_record.id, actor: subscriber)
      assert {:error, _not_found} = Cases.get_case(case_record.id, actor: outsider)
    end

    test "deleting the list ends the access", %{
      case: case_record,
      list: list,
      poc: poc,
      subscriber: subscriber
    } do
      Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)
      Predisclosure.destroy_predisclosure_list!(list, actor: poc)

      assert {:error, _not_found} = Cases.get_case(case_record.id, actor: subscriber)
    end
  end

  describe "notifications" do
    test "sharing a case notifies the subscribers once", %{poc: poc, subscriber: subscriber} do
      list = list(poc)
      Predisclosure.subscribe_to_predisclosure_list!(list.id, subscriber.id, actor: poc)
      case_record = Fixtures.open_case(poc)

      case_record = Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)
      Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)
      drain()

      assert [%Notification{count: 1, case_id: case_id}] = shared_notifications(subscriber)
      assert case_id == case_record.id
      assert [] = shared_notifications(poc)
    end

    test "a new subscriber hears of every case the list holds", %{
      poc: poc,
      subscriber: subscriber
    } do
      list = list(poc)
      first = Fixtures.open_case(poc)
      second = Fixtures.open_case(poc)
      Cases.set_case_predisclosure_lists!(first, [list.id], actor: poc)
      Cases.set_case_predisclosure_lists!(second, [list.id], actor: poc)

      Predisclosure.subscribe_to_predisclosure_list!(list.id, subscriber.id, actor: poc)
      drain()

      assert subscriber |> shared_notifications() |> Enum.map(& &1.case_id) |> Enum.sort() ==
               Enum.sort([first.id, second.id])
    end
  end
end
