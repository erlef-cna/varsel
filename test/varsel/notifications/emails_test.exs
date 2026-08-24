# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.EmailsTest do
  @moduledoc """
  The :email trigger, the :send_digests scheduled action, and the bodies
  Varsel.Notifications.Emails builds: content-free, one mail per unread row,
  a digest listing counts per kind.
  """

  use Varsel.DataCase, async: false

  alias Varsel.Accounts
  alias Varsel.Cases
  alias Varsel.CVE
  alias Varsel.Fixtures
  alias Varsel.Notifications
  alias Varsel.Notifications.Notification
  alias Varsel.Service

  require Ash.Query

  defp drain(opts \\ []) do
    Oban.drain_queue(Keyword.merge([queue: :default, with_recursion: true], opts))
  end

  # Drains every email the Swoosh Test adapter delivered to this process.
  defp sent_emails(acc \\ []) do
    receive do
      {:email, email} -> sent_emails([email | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp notifications_for(user) do
    Notification
    |> Ash.Query.filter(user_id == ^user.id)
    |> Ash.read!(authorize?: false)
  end

  defp send_digests do
    perform_job(Varsel.Notifications.Notification.SendDigestsWorker, %{})
  end

  describe ":report_submitted" do
    test "submitting a report emails every POC with a /reports link, not the reporter" do
      Fixtures.register_user("emails_report_poc_one", :poc)
      Fixtures.register_user("emails_report_poc_two", :poc)
      reporter = Fixtures.register_user("emails_report_reporter", :supporter)

      {:ok, _report} =
        CVE.submit_vulnerability_report(
          %{
            report_json: %{"affected" => "pkg"},
            summary: "a bug",
            confirms_criteria: true,
            confirms_in_scope: true
          },
          actor: reporter
        )

      drain()

      emails = sent_emails()

      recipients =
        for {_name, addr} <- Enum.flat_map(emails, & &1.to), into: MapSet.new(), do: addr

      assert "emails_report_poc_one@example.com" in recipients
      assert "emails_report_poc_two@example.com" in recipients
      refute "emails_report_reporter@example.com" in recipients

      body = hd(emails).text_body
      assert body =~ "/reports"
      refute body =~ "pkg"
      refute body =~ "emails_report_reporter@example.com"
    end

    test "hex.pm intake emails every POC too, with no payload or participant text" do
      Fixtures.register_user("emails_hex_report_poc", :poc)

      {:ok, _report} =
        CVE.submit_hex_vulnerability_report(
          %{
            report_json: %{"affected" => "secret_pkg"},
            summary: "a bug",
            participants: [%{role: :reporter, strategy: :hex, username: "somebody"}]
          },
          actor: Service.hexpm_intake()
        )

      drain()

      assert [%{to: [{_name, "emails_hex_report_poc@example.com"}]} = email] = sent_emails()
      assert email.text_body =~ "/reports"
      refute email.text_body =~ "secret_pkg"
      refute email.text_body =~ "somebody"
    end
  end

  describe "the :email trigger" do
    test "posting a comment emails the assigned POC with a case link and no comment body" do
      poc = Fixtures.register_user("emails_comment_poc", :poc)
      supporter = Fixtures.register_user("emails_comment_supporter", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      drain()
      sent_emails()

      Cases.post_case_comment!(
        %{case_id: case_record.id, body: "a very specific comment body"},
        actor: supporter
      )

      drain()

      assert [%{to: [{_name, "emails_comment_poc@example.com"}]} = email] = sent_emails()
      assert email.subject =~ "New comment"
      assert email.text_body =~ "/cases/#{case_record.id}"
      refute email.text_body =~ "a very specific comment body"
      refute email.text_body =~ case_record.title

      assert [%Notification{emailed_at: %DateTime{}}] = notifications_for(poc)
    end

    test "a second comment before the first row is read does not send a second email" do
      poc = Fixtures.register_user("emails_absorb_poc", :poc)
      supporter = Fixtures.register_user("emails_absorb_supporter", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      drain()
      sent_emails()

      Cases.post_case_comment!(%{case_id: case_record.id, body: "first"}, actor: supporter)
      drain()
      Cases.post_case_comment!(%{case_id: case_record.id, body: "second"}, actor: supporter)
      drain()

      assert [_one_email] = sent_emails()
      assert [%Notification{count: 2, emailed_at: %DateTime{}}] = notifications_for(poc)
    end

    test "a comment after the row is read starts a new row and a new email" do
      poc = Fixtures.register_user("emails_reread_poc", :poc)
      supporter = Fixtures.register_user("emails_reread_supporter", :supporter)

      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      drain()
      sent_emails()

      Cases.post_case_comment!(%{case_id: case_record.id, body: "first"}, actor: supporter)
      drain()
      assert [_first_email] = sent_emails()

      [notification] = notifications_for(poc)
      Notifications.mark_notification_read!(notification, actor: poc)

      Cases.post_case_comment!(%{case_id: case_record.id, body: "second"}, actor: supporter)
      drain()

      assert [_second_email] = sent_emails()
      assert [_read_row, _new_row] = notifications_for(poc)
    end

    test "email: false records the notification but sends no mail" do
      poc = Fixtures.register_user("emails_pref_off_poc", :poc)
      other_poc = Fixtures.register_user("emails_pref_off_other", :poc)

      Accounts.update_user_notification_settings!(
        poc,
        %{notification_preferences: [%{kind: :review_requested, in_app: true, email: false}]},
        actor: poc
      )

      case_record = Fixtures.open_case(other_poc)
      Cases.request_case_review!(case_record, actor: other_poc)

      drain()

      assert [] = sent_emails()
      assert [%Notification{email_requested: false}] = notifications_for(poc)
    end

    test "a user with no notification_email is skipped, and the row is still stamped so the trigger stops re-selecting it" do
      poc = Fixtures.register_user("emails_no_address_poc", :poc)
      other_poc = Fixtures.register_user("emails_no_address_other", :poc)

      Ash.update!(poc, %{notification_email: nil},
        action: :set_notification_email,
        authorize?: false
      )

      case_record = Fixtures.open_case(other_poc)
      Cases.request_case_review!(case_record, actor: other_poc)

      drain()

      assert [] = sent_emails()
      assert [%Notification{emailed_at: %DateTime{}}] = notifications_for(poc)
    end

    test "daily_digest mode sends nothing on the immediate trigger" do
      poc = Fixtures.register_user("emails_digest_mode_poc", :poc)
      other_poc = Fixtures.register_user("emails_digest_mode_other", :poc)

      Accounts.update_user_notification_settings!(
        poc,
        %{notification_email_mode: :daily_digest},
        actor: poc
      )

      case_record = Fixtures.open_case(other_poc)
      Cases.request_case_review!(case_record, actor: other_poc)

      drain()

      assert [] = sent_emails()
      assert [%Notification{emailed_at: nil}] = notifications_for(poc)
    end
  end

  describe ":send_digests" do
    test "emails a daily_digest user one mail listing counts per kind and stamps every covered row" do
      poc = Fixtures.register_user("emails_send_digest_poc", :poc)
      other_poc = Fixtures.register_user("emails_send_digest_other", :poc)
      supporter = Fixtures.register_user("emails_send_digest_supporter", :supporter)

      Accounts.update_user_notification_settings!(
        poc,
        %{notification_email_mode: :daily_digest},
        actor: poc
      )

      case_one = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_one.id, user_id: supporter.id}, actor: poc)
      drain()
      # The assignment itself emails the (immediate-mode) supporter; drop it
      # so it doesn't pollute the digest assertion below.
      sent_emails()

      Cases.post_case_comment!(%{case_id: case_one.id, body: "hi"}, actor: supporter)
      Cases.request_case_review!(Fixtures.open_case(other_poc), actor: other_poc)

      drain()

      send_digests()

      assert [%{to: [{_name, "emails_send_digest_poc@example.com"}]} = email] = sent_emails()
      assert email.subject =~ "daily notification digest"
      assert email.text_body =~ "1 × New comment"
      assert email.text_body =~ "1 × Review requested"
      assert email.text_body =~ "/notifications"

      assert poc
             |> notifications_for()
             |> Enum.all?(&(&1.emailed_at != nil))
    end

    test "a read row is not included in the digest" do
      poc = Fixtures.register_user("emails_digest_read_poc", :poc)
      other_poc = Fixtures.register_user("emails_digest_read_other", :poc)

      Accounts.update_user_notification_settings!(
        poc,
        %{notification_email_mode: :daily_digest},
        actor: poc
      )

      read_case = Fixtures.open_case(other_poc)
      Cases.request_case_review!(read_case, actor: other_poc)
      drain()

      [read_notification] = notifications_for(poc)
      Notifications.mark_notification_read!(read_notification, actor: poc)

      unread_case = Fixtures.open_case(other_poc)
      Cases.assign_case_user!(%{case_id: unread_case.id, user_id: poc.id}, actor: other_poc)
      drain()

      send_digests()

      assert [%{to: [{_name, "emails_digest_read_poc@example.com"}]} = email] = sent_emails()
      assert email.text_body =~ "1 × Added to a case"
      refute email.text_body =~ "Review requested"
    end

    test "no pending rows sends no email" do
      poc = Fixtures.register_user("emails_digest_empty_poc", :poc)

      Accounts.update_user_notification_settings!(
        poc,
        %{notification_email_mode: :daily_digest},
        actor: poc
      )

      send_digests()

      assert [] = sent_emails()
    end

    test "a row pending under :immediate mode is not sent immediately once the user switches to :daily_digest, and the next digest run covers it" do
      poc = Fixtures.register_user("emails_switch_to_digest_poc", :poc)
      other_poc = Fixtures.register_user("emails_switch_to_digest_other", :poc)

      case_record = Fixtures.open_case(other_poc)
      Cases.request_case_review!(case_record, actor: other_poc)

      # Run only the fan-out job (the single job queued so far), so the row
      # (and its freshly-enqueued :email trigger job) exists while the user
      # is still in :immediate mode, without running that trigger job yet.
      # with_recursion must be off here or the newly-enqueued :email job
      # runs in the same call.
      drain(with_limit: 1, with_recursion: false)

      [notification] = notifications_for(poc)
      assert notification.emailed_at == nil

      Accounts.update_user_notification_settings!(
        poc,
        %{notification_email_mode: :daily_digest},
        actor: poc
      )

      # The :email trigger job runs now, but its own re-check sees the row no
      # longer matches (mode switched), so it cancels without sending.
      perform_job(Varsel.Notifications.Notification.EmailWorker, %{
        "primary_key" => %{"id" => notification.id}
      })

      assert [] = sent_emails()
      assert [%Notification{emailed_at: nil}] = notifications_for(poc)

      send_digests()

      assert [%{to: [{_name, "emails_switch_to_digest_poc@example.com"}]}] = sent_emails()
      assert [%Notification{emailed_at: %DateTime{}}] = notifications_for(poc)
    end
  end

  describe "the EmailScheduler safety net" do
    test "selects only immediate-mode pending rows" do
      immediate_poc = Fixtures.register_user("emails_scheduler_immediate_poc", :poc)
      digest_poc = Fixtures.register_user("emails_scheduler_digest_poc", :poc)
      other_poc = Fixtures.register_user("emails_scheduler_other", :poc)

      Accounts.update_user_notification_settings!(
        digest_poc,
        %{notification_email_mode: :daily_digest},
        actor: digest_poc
      )

      case_record = Fixtures.open_case(other_poc)
      Cases.request_case_review!(case_record, actor: other_poc)

      perform_job(Varsel.Notifications.Notification.EmailScheduler, %{})
      drain()

      emails = sent_emails()

      recipients =
        for {_name, addr} <- Enum.flat_map(emails, & &1.to), into: MapSet.new(), do: addr

      assert "emails_scheduler_immediate_poc@example.com" in recipients
      refute "emails_scheduler_digest_poc@example.com" in recipients

      assert [%Notification{emailed_at: %DateTime{}}] = notifications_for(immediate_poc)
      assert [%Notification{emailed_at: nil}] = notifications_for(digest_poc)
    end
  end

  describe "policies" do
    test "Ash.can? denies :send_email and :send_digests to a POC" do
      poc = Fixtures.register_user("emails_can_poc", :poc)
      refute Ash.can?({Notification, :send_email}, poc)
      refute Ash.can?({Notification, :send_digests}, poc)
    end
  end
end
