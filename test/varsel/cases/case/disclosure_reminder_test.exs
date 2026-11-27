# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.DisclosureReminderTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.Cases.Case
  alias Varsel.Fixtures
  alias Varsel.Notifications.Notification

  require Ash.Query

  setup do
    poc = Fixtures.register_user("reminder_poc_#{System.unique_integer([:positive])}", :poc)

    supporter =
      Fixtures.register_user(
        "reminder_supporter_#{System.unique_integer([:positive])}",
        :supporter
      )

    case_record = Fixtures.open_case(poc)
    Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
    remind()

    %{poc: poc, supporter: supporter, case: case_record}
  end

  defp remind do
    AshOban.Test.schedule_and_run_triggers({Case, :remind_disclosure_overdue},
      scheduled_actions?: false
    )

    Oban.drain_queue(queue: :default, with_recursion: true)
  end

  defp plan(case_record, poc, hours_ago) do
    at = DateTime.utc_now() |> DateTime.shift(hour: -hours_ago) |> DateTime.truncate(:second)
    Cases.edit_case!(case_record, %{planned_disclosure_at: at}, actor: poc)
  end

  defp reminders(user) do
    Notification
    |> Ash.Query.filter(user_id == ^user.id and kind == :disclosure_overdue)
    |> Ash.read!(authorize?: false)
  end

  test "a date more than 8 hours past reminds everyone on the case once", %{
    poc: poc,
    supporter: supporter,
    case: case_record
  } do
    plan(case_record, poc, 9)
    remind()
    remind()

    assert [%Notification{count: 1}] = reminders(poc)
    assert [%Notification{count: 1}] = reminders(supporter)
  end

  test "a date less than 8 hours past does not remind yet", %{poc: poc, case: case_record} do
    plan(case_record, poc, 7)
    remind()

    assert [] = reminders(poc)
  end

  test "a new date that passes as well reminds again", %{poc: poc, case: case_record} do
    case_record = plan(case_record, poc, 30)
    remind()
    plan(case_record, poc, 9)
    remind()

    assert [%Notification{read_at: nil}] = Enum.reject(reminders(poc), & &1.read_at)
    assert length(reminders(poc)) == 2
  end

  test "changing the date marks the reminder read for everyone", %{
    poc: poc,
    supporter: supporter,
    case: case_record
  } do
    case_record = plan(case_record, poc, 9)
    remind()

    Cases.edit_case!(case_record, %{planned_disclosure_at: ~U[2030-03-01 12:00:00Z]}, actor: poc)
    Oban.drain_queue(queue: :default, with_recursion: true)

    assert [%Notification{read_at: %DateTime{}}] = reminders(poc)
    assert [%Notification{read_at: %DateTime{}}] = reminders(supporter)
  end

  test "an accepted suggestion that clears the date marks the reminder read", %{
    poc: poc,
    supporter: supporter,
    case: case_record
  } do
    plan(case_record, poc, 9)
    remind()

    proposal =
      Cases.propose_planned_disclosure!(%{case_id: case_record.id, value: nil}, actor: supporter)

    Cases.accept_case_proposal!(proposal, %{}, actor: poc)
    Oban.drain_queue(queue: :default, with_recursion: true)

    assert [%Notification{read_at: %DateTime{}}] = reminders(poc)
  end

  test "an edit that leaves the date alone keeps the reminder unread", %{
    poc: poc,
    case: case_record
  } do
    case_record = plan(case_record, poc, 9)
    remind()

    Cases.edit_case!(case_record, %{title: "Still overdue"}, actor: poc)
    Oban.drain_queue(queue: :default, with_recursion: true)

    assert [%Notification{read_at: nil}] = reminders(poc)
  end

  test "a case that was published once is not reminded", %{poc: poc, case: case_record} do
    case_record = plan(case_record, poc, 9)
    Ash.Seed.update!(case_record, %{published_at: DateTime.utc_now(:second)})
    remind()

    assert [] = reminders(poc)
  end

  test "a closed case is not reminded", %{poc: poc, case: case_record} do
    case_record = plan(case_record, poc, 9)
    Ash.Seed.update!(case_record, %{state: :closed})
    remind()

    assert [] = reminders(poc)
  end

  test "only the scheduler sends a reminder", %{poc: poc, case: case_record} do
    case_record = plan(case_record, poc, 9)

    assert {:error, %Forbidden{}} =
             case_record
             |> Ash.Changeset.for_update(:remind_disclosure_overdue, %{}, actor: poc)
             |> Ash.update()
  end
end
