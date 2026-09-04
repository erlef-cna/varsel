# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.FanOutTest do
  @moduledoc """
  Event -> FanOut -> Notification, per source kind: the right audience, the
  actor excluded, preferences honoured.
  """

  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.CVE
  alias Varsel.Fixtures
  alias Varsel.Notifications
  alias Varsel.Notifications.Event
  alias Varsel.Notifications.Notification
  alias Varsel.Service

  require Ash.Query

  defp drain do
    Oban.drain_queue(queue: :default, with_recursion: true)
  end

  defp notifications_for(user) do
    Notification
    |> Ash.Query.filter(user_id == ^user.id)
    |> Ash.read!(authorize?: false)
  end

  defp notifications_for(user, kind) do
    user |> notifications_for() |> Enum.filter(&(&1.kind == kind))
  end

  describe ":report_submitted" do
    test "notifies every POC, not the reporter" do
      poc_one = Fixtures.register_user("fanout_poc_one", :poc)
      poc_two = Fixtures.register_user("fanout_poc_two", :poc)
      reporter = Fixtures.register_user("fanout_reporter", :supporter)

      {:ok, _report} =
        CVE.submit_vulnerability_report(
          %{
            report_json: %{"x" => 1},
            summary: "a bug",
            confirms_criteria: true,
            confirms_in_scope: true
          },
          actor: reporter
        )

      drain()

      assert [%Notification{kind: :report_submitted}] = notifications_for(poc_one)
      assert [%Notification{kind: :report_submitted}] = notifications_for(poc_two)
      assert [] = notifications_for(reporter)
    end

    test "hex.pm intake notifies every POC too" do
      poc = Fixtures.register_user("fanout_hex_poc", :poc)

      {:ok, _report} =
        CVE.submit_hex_vulnerability_report(
          %{
            report_json: %{"x" => 1},
            summary: "a bug",
            participants: [
              %{role: :reporter, strategy: :hex, username: "somebody"}
            ]
          },
          actor: Service.hexpm_intake()
        )

      drain()

      assert [%Notification{kind: :report_submitted}] = notifications_for(poc)
    end
  end

  describe ":review_requested" do
    test "notifies every POC, not the requester" do
      poc_one = Fixtures.register_user("fanout_review_poc_one", :poc)
      poc_two = Fixtures.register_user("fanout_review_poc_two", :poc)

      case_record = Fixtures.open_case(poc_one)
      Cases.request_case_review!(case_record, actor: poc_one)

      drain()

      # poc_one opened (and is assigned to) the case and also requested
      # review as its actor, so they get nothing for this event.
      assert [] = notifications_for(poc_one)
      assert [%Notification{kind: :review_requested}] = notifications_for(poc_two)
    end
  end

  describe ":comment_posted" do
    test "notifies assigned users, not an unassigned POC, not the commenter" do
      poc = Fixtures.register_user("fanout_comment_poc", :poc)
      assigned = Fixtures.register_user("fanout_comment_assigned", :supporter)
      unassigned_poc = Fixtures.register_user("fanout_comment_other_poc", :poc)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: assigned.id}, actor: poc)

      Cases.post_case_comment!(
        %{case_id: case_record.id, body: "hello"},
        actor: assigned
      )

      drain()

      # poc is assigned (opener) and a POC, but not the commenter -> notified.
      assert [%Notification{kind: :comment_posted, count: 1}] =
               notifications_for(poc, :comment_posted)

      # the commenter themself gets nothing for their own comment.
      assert [] = notifications_for(assigned, :comment_posted)
      # a POC who is not assigned to the case gets nothing (audience is
      # :assigned, not :pocs).
      assert [] = notifications_for(unassigned_poc, :comment_posted)
    end

    test "two comments by the same other user absorb into one row with count 2" do
      poc = Fixtures.register_user("fanout_comment_count_poc", :poc)
      other = Fixtures.register_user("fanout_comment_count_other", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: other.id}, actor: poc)

      Cases.post_case_comment!(%{case_id: case_record.id, body: "first"}, actor: other)
      drain()
      Cases.post_case_comment!(%{case_id: case_record.id, body: "second"}, actor: other)
      drain()

      assert [%Notification{count: 2}] = notifications_for(poc)
    end
  end

  describe ":proposal_opened" do
    test "notifies assigned users, not the proposer" do
      poc = Fixtures.register_user("fanout_proposal_poc", :poc)
      other = Fixtures.register_user("fanout_proposal_other", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: other.id}, actor: poc)

      Cases.propose_title!(
        %{case_id: case_record.id, value: "New title"},
        actor: other
      )

      drain()

      assert [%Notification{kind: :proposal_opened}] = notifications_for(poc, :proposal_opened)
      assert [] = notifications_for(other, :proposal_opened)
    end
  end

  describe ":case_assigned" do
    test "notifies only the assigned user, not the assigning POC" do
      poc = Fixtures.register_user("fanout_assign_poc", :poc)
      assignee = Fixtures.register_user("fanout_assignee", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: assignee.id}, actor: poc)

      drain()

      assert [%Notification{kind: :case_assigned}] = notifications_for(assignee)
      assert [] = notifications_for(poc)
    end

    test "self-assignment (Case.open assigning its own opener) raises no event" do
      poc = Fixtures.register_user("fanout_self_assign_poc", :poc)

      Fixtures.open_case(poc)

      assert [] =
               Event
               |> Ash.Query.filter(kind == :case_assigned)
               |> Ash.read!(authorize?: false)
    end

    test "the invite-claim path notifies the claimer" do
      Req.Test.stub(Varsel.Accounts.GitHub, fn conn ->
        login = conn.request_path |> Path.basename() |> URI.decode() |> String.downcase()
        Req.Test.json(conn, %{"login" => login, "email" => "#{login}@example.com"})
      end)

      poc = Fixtures.register_user("fanout_invite_poc", :poc)
      case_record = Fixtures.open_case(poc)

      Cases.invite_to_case!(
        %{case_id: case_record.id, strategy: :github, username: "fanout_claimer"},
        actor: poc
      )

      claimer = Fixtures.register_user("fanout_claimer")

      drain()

      assert [%Notification{kind: :case_assigned}] = notifications_for(claimer)
    end
  end

  describe ":case_published" do
    test "notifies assigned users once the case is marked published" do
      poc = Fixtures.register_user("fanout_publish_poc", :poc)
      assigned = Fixtures.register_user("fanout_publish_assigned", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: assigned.id}, actor: poc)

      # Seeds straight into :publishing and runs :mark_published under the
      # actor-less, ash_oban?-flagged context AshOban runs it under.
      case_record = Ash.Seed.update!(case_record, %{state: :publishing})

      case_record
      |> Ash.Changeset.for_update(:mark_published, %{}, context: %{private: %{ash_oban?: true}})
      |> Ash.update!()

      drain()

      # mark_published has no actor to exclude, so every assigned user
      # (including the opener) is notified.
      assert [%Notification{kind: :case_published}] = notifications_for(assigned, :case_published)
      assert [%Notification{kind: :case_published}] = notifications_for(poc, :case_published)
    end
  end

  describe "preferences" do
    test "in_app: false suppresses the notification" do
      poc = Fixtures.register_user("fanout_pref_inapp_poc", :poc)
      other_poc = Fixtures.register_user("fanout_pref_inapp_other", :poc)

      Ash.update!(
        poc,
        %{notification_preferences: [%{kind: :review_requested, in_app: false, email: true}]},
        action: :update_notification_settings,
        actor: poc
      )

      case_record = Fixtures.open_case(other_poc)
      Cases.request_case_review!(case_record, actor: other_poc)

      drain()

      assert [] = notifications_for(poc)
    end

    test "email: false still records the notification, with email_requested: false" do
      poc = Fixtures.register_user("fanout_pref_email_poc", :poc)
      other_poc = Fixtures.register_user("fanout_pref_email_other", :poc)

      Ash.update!(
        poc,
        %{notification_preferences: [%{kind: :review_requested, in_app: true, email: false}]},
        action: :update_notification_settings,
        actor: poc
      )

      case_record = Fixtures.open_case(other_poc)
      Cases.request_case_review!(case_record, actor: other_poc)

      drain()

      assert [%Notification{email_requested: false}] = notifications_for(poc)
    end
  end

  test "processed_at is stamped once the fan-out worker runs" do
    poc = Fixtures.register_user("fanout_processed_poc", :poc)
    other_poc = Fixtures.register_user("fanout_processed_other", :poc)

    case_record = Fixtures.open_case(other_poc)
    Cases.request_case_review!(case_record, actor: other_poc)

    assert [%Event{kind: :review_requested} = event] =
             Event
             |> Ash.Query.filter(kind == :review_requested)
             |> Ash.read!(authorize?: false)

    assert is_nil(event.processed_at)

    drain()

    reloaded = Ash.get!(Event, event.id, authorize?: false)
    assert reloaded.processed_at

    assert [%Notification{kind: :review_requested}] = notifications_for(poc, :review_requested)
  end

  test "a fan-out failure leaves processed_at nil and records no notifications" do
    poc = Fixtures.register_user("fanout_failure_poc", :poc)
    case_record = Fixtures.open_case(poc)

    # Ash.Seed.seed! skips validations, so this can force the inconsistent
    # row RecipientMatchesAudience would otherwise reject: a :case_assigned
    # event (audience :recipient) with no recipient_id, which fails the
    # fan-out's Ash.get!(User, nil, ...) lookup.
    event =
      Ash.Seed.seed!(Event, %{kind: :case_assigned, case_id: case_record.id, processed_at: nil})

    AshOban.run_trigger(event, :fan_out)
    result = Oban.drain_queue(queue: :default)

    assert result.failure == 1

    reloaded = Ash.get!(Event, event.id, authorize?: false)
    assert is_nil(reloaded.processed_at)
    assert [] = notifications_for(poc)
  end

  describe "recipient_id matches Kind.audience" do
    test "a :recipient kind (case_assigned) without recipient_id is rejected" do
      poc = Fixtures.register_user("fanout_missing_recipient_poc", :poc)
      case_record = Fixtures.open_case(poc)

      assert {:error, error} =
               Notifications.emit_notification_event(
                 %{kind: :case_assigned, case_id: case_record.id},
                 actor: Service.notifier()
               )

      assert Exception.message(error) =~ "is required"
    end

    test "a non-:recipient kind (review_requested) with recipient_id is rejected" do
      poc = Fixtures.register_user("fanout_extra_recipient_poc", :poc)
      other = Fixtures.register_user("fanout_extra_recipient_other", :poc)
      case_record = Fixtures.open_case(poc)

      assert {:error, error} =
               Notifications.emit_notification_event(
                 %{kind: :review_requested, case_id: case_record.id, recipient_id: other.id},
                 actor: Service.notifier()
               )

      assert Exception.message(error) =~ "must be nil"
    end
  end

  describe "direct access to Event" do
    test "emitting directly as a POC is Forbidden" do
      poc = Fixtures.register_user("fanout_direct_emit_poc", :poc)
      case_record = Fixtures.open_case(poc)

      assert {:error, %Forbidden{}} =
               Notifications.emit_notification_event(
                 %{kind: :review_requested, case_id: case_record.id},
                 actor: poc
               )
    end

    test "Ash.can? denies :emit to a POC" do
      poc = Fixtures.register_user("fanout_can_emit_poc", :poc)
      refute Ash.can?({Event, :emit}, poc)
    end

    test "a POC reading events directly is Forbidden" do
      poc = Fixtures.register_user("fanout_read_events_poc", :poc)
      assert {:error, %Forbidden{}} = Notifications.read_notification_events(actor: poc)
    end
  end
end
