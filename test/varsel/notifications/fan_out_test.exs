# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.FanOutTest do
  @moduledoc """
  Signal -> FanOut -> Notification, per source kind: the right audience, the
  actor excluded, preferences honoured.
  """

  use Varsel.DataCase, async: true

  import Ash.Signals.Test

  alias Ash.Error.Forbidden
  alias AshOban.Signals.Worker
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Notifications
  alias Varsel.Notifications.Notification
  alias Varsel.Service
  alias Varsel.Test.GitHubApi
  alias Varsel.Test.GitHubApp

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
        Cases.submit_vulnerability_report(
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

      Req.Test.stub(Varsel.HexPm, fn conn ->
        Req.Test.json(conn, %{"username" => "somebody", "name" => "somebody", "email" => nil})
      end)

      {:ok, _report} =
        Cases.submit_hex_vulnerability_report(
          %{
            report_json: %{"x" => 1},
            summary: "a bug",
            reporter_username: "somebody",
            maintainers: []
          },
          actor: Service.hexpm_intake()
        )

      drain()

      assert [%Notification{kind: :report_submitted}] = notifications_for(poc)
    end
  end

  describe ":review_requested" do
    test "notifies the POCs assigned to the case, not other POCs, supporters or the requester" do
      assigned_poc = Fixtures.register_user("fanout_review_assigned_poc", :poc)
      other_poc = Fixtures.register_user("fanout_review_other_poc", :poc)
      requester = Fixtures.register_user("fanout_review_requester", :supporter)
      fellow = Fixtures.register_user("fanout_review_fellow", :supporter)

      case_record = Fixtures.open_case(requester)

      for user <- [assigned_poc, fellow] do
        Cases.assign_case_user!(%{case_id: case_record.id, user_id: user.id}, actor: assigned_poc)
      end

      Cases.request_case_review!(case_record, actor: requester)

      drain()

      assert [%Notification{kind: :review_requested}] =
               notifications_for(assigned_poc, :review_requested)

      assert [] = notifications_for(other_poc, :review_requested)
      assert [] = notifications_for(fellow, :review_requested)
      assert [] = notifications_for(requester, :review_requested)
    end

    test "a review a POC requests notifies nobody, not even the other assigned POCs" do
      poc = Fixtures.register_user("fanout_review_self_poc", :poc)
      fellow_poc = Fixtures.register_user("fanout_review_fellow_poc", :poc)

      case_record = Fixtures.open_case(poc)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: fellow_poc.id},
        actor: fellow_poc
      )

      Cases.request_case_review!(case_record, actor: poc)

      drain()

      assert [] = notifications_for(poc, :review_requested)
      assert [] = notifications_for(fellow_poc, :review_requested)
    end

    test "is refused while no POC is assigned, and notifies nobody" do
      poc = Fixtures.register_user("fanout_review_unassigned_poc", :poc)
      requester = Fixtures.register_user("fanout_review_lone_supporter", :supporter)

      case_record = Fixtures.open_case(requester)

      refute Cases.can_request_case_review?(requester, case_record, validate?: true)

      assert {:error, %Ash.Error.Invalid{}} =
               Cases.request_case_review(case_record, actor: requester)

      refute_enqueued worker: Worker, args: %{"listener" => "notify_review_requested"}

      drain()

      assert [] = notifications_for(poc, :review_requested)
    end
  end

  describe ":mentioned" do
    alias Varsel.Cases.Comment.Mentions

    test "notifies the mentioned who may read the case, not the writer" do
      poc = Fixtures.register_user("fanout_mention_poc", :poc)
      assigned = Fixtures.register_user("fanout_mention_assigned", :supporter)
      other_poc = Fixtures.register_user("fanout_mention_other_poc", :poc)
      outsider = Fixtures.register_user("fanout_mention_outsider", :supporter)
      bystander = Fixtures.register_user("fanout_mention_bystander", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: assigned.id}, actor: poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: bystander.id}, actor: poc)

      body =
        Enum.map_join(
          [assigned, other_poc, outsider, poc],
          " ",
          &Mentions.token(&1.id, "someone")
        )

      Cases.post_case_comment!(%{case_id: case_record.id, body: body}, actor: poc)

      drain()

      assert [%Notification{case_id: case_id}] = notifications_for(assigned, :mentioned)
      assert case_id == case_record.id
      # A POC reads every case, so a mention reaches one who is not assigned.
      assert [%Notification{}] = notifications_for(other_poc, :mentioned)
      # Someone the case is hidden from learns nothing of it.
      assert [] = notifications_for(outsider)
      assert [] = notifications_for(bystander, :mentioned)
      assert [] = notifications_for(poc, :mentioned)
    end

    test "a mention inside code mentions no one" do
      poc = Fixtures.register_user("fanout_mention_code_poc", :poc)
      other_poc = Fixtures.register_user("fanout_mention_code_other", :poc)
      case_record = Fixtures.open_case(poc)

      Cases.post_case_comment!(
        %{case_id: case_record.id, body: "`#{Mentions.token(other_poc.id, "x")}`"},
        actor: poc
      )

      drain()

      assert [] = notifications_for(other_poc, :mentioned)
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

    test "a repeat assignment raises no second event" do
      poc = Fixtures.register_user("fanout_reassign_poc", :poc)
      assignee = Fixtures.register_user("fanout_reassignee", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: assignee.id}, actor: poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: assignee.id}, actor: poc)

      drain()

      assert [%Notification{kind: :case_assigned}] = notifications_for(assignee)
    end

    test "self-assignment (Case.open assigning its own opener) notifies nobody" do
      poc = Fixtures.register_user("fanout_self_assign_poc", :poc)

      Fixtures.open_case(poc)

      drain()

      assert [] = notifications_for(poc, :case_assigned)
    end

    test "the invite-claim path notifies the claimer" do
      GitHubApp.seed_installation(%{id: 1, account: "erlef-cna"}, token: "ghs_erlef_cna")

      GitHubApi.stub(fn conn ->
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

      Ash.update!(
        poc,
        %{notification_preferences: [%{kind: :review_requested, in_app: false, email: true}]},
        action: :update_notification_settings,
        actor: poc
      )

      Fixtures.request_review_for(poc)

      drain()

      assert [] = notifications_for(poc)
    end

    test "email: false still records the notification, with email_requested: false" do
      poc = Fixtures.register_user("fanout_pref_email_poc", :poc)

      Ash.update!(
        poc,
        %{notification_preferences: [%{kind: :review_requested, in_app: true, email: false}]},
        action: :update_notification_settings,
        actor: poc
      )

      Fixtures.request_review_for(poc)

      drain()

      assert [%Notification{email_requested: false}] = notifications_for(poc)
    end
  end

  describe "the fan-out job" do
    test "is enqueued with the source write and runs after it" do
      poc = Fixtures.register_user("fanout_enqueued_poc", :poc)

      Fixtures.request_review_for(poc)

      assert_enqueued worker: Worker,
                      queue: :default,
                      args: %{"listener" => "notify_review_requested"}

      assert [] = notifications_for(poc)

      drain()

      assert [%Notification{kind: :review_requested}] = notifications_for(poc, :review_requested)
    end

    test "is rolled back with the source write" do
      other_poc = Fixtures.register_user("fanout_rollback_other", :poc)
      case_record = Fixtures.open_case(other_poc)

      assert {:error, :rolled_back} =
               Varsel.Repo.transaction(fn ->
                 Cases.request_case_review!(case_record,
                   actor: other_poc,
                   return_notifications?: true
                 )

                 Varsel.Repo.rollback(:rolled_back)
               end)

      refute_enqueued worker: Worker,
                      args: %{"listener" => "notify_review_requested"}
    end

    test "a failure fails the job and records no notifications" do
      poc = Fixtures.register_user("fanout_failure_poc", :poc)
      case_record = Fixtures.open_case(poc)

      # Nobody holds this id, so the fan-out's lookup of the recipient raises.
      :ok =
        react_to_signal(
          Cases.Signals,
          :case_assigned,
          %{case_id: case_record.id, user_id: Ash.UUID.generate()},
          only: Notification
        )

      assert %{failure: 1} = Oban.drain_queue(queue: :default)
      assert [] = notifications_for(poc)
    end
  end

  describe "direct access to :fan_out" do
    setup do
      poc = Fixtures.register_user("fanout_direct_poc", :poc)
      case_record = Fixtures.open_case(poc)

      signal = %Cases.Signals.ReviewRequested{
        signal_id: Ash.UUIDv7.generate(),
        case_id: case_record.id
      }

      %{poc: poc, signal: signal}
    end

    test "is Forbidden to an anonymous caller", %{signal: signal} do
      assert {:error, %Forbidden{}} = fan_out(signal, nil)
    end

    test "is Forbidden to a role-less user", %{signal: signal} do
      assert {:error, %Forbidden{}} =
               fan_out(signal, Fixtures.register_user("fanout_direct_roleless"))
    end

    test "is Forbidden to a POC", %{poc: poc, signal: signal} do
      assert {:error, %Forbidden{}} = fan_out(signal, poc)
      refute Notifications.can_fan_out_notifications?(poc, signal)
    end
  end

  defp fan_out(signal, actor) do
    Notifications.fan_out_notifications(signal, actor: actor)
  end
end
