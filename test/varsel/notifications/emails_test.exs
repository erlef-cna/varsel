# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.EmailsTest do
  @moduledoc """
  The :email trigger, the :send_digests scheduled action, and the bodies
  Varsel.Notifications.Emails builds: content-free, one mail per unread row,
  a digest listing counts per kind.
  """

  use Varsel.DataCase, async: true

  alias Varsel.Accounts
  alias Varsel.Cases
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
    test "submitting a report emails every POC with a link to its case, not the reporter" do
      Fixtures.register_user("emails_report_poc_one", :poc)
      Fixtures.register_user("emails_report_poc_two", :poc)
      reporter = Fixtures.register_user("emails_report_reporter", :supporter)

      {:ok, case_record} =
        Cases.submit_vulnerability_report(
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
      assert body =~ "/cases/#{case_record.id}"
      refute body =~ "pkg"
      refute body =~ "emails_report_reporter@example.com"
    end

    test "hex.pm intake emails every POC too, with no payload or reporter text" do
      Fixtures.register_user("emails_hex_report_poc", :poc)

      # No address, so the reporter's invite sends no email of its own.
      Req.Test.stub(Varsel.HexPm, fn conn ->
        Req.Test.json(conn, %{"username" => "somebody", "name" => "somebody", "email" => nil})
      end)

      {:ok, _report} =
        Cases.submit_hex_vulnerability_report(
          %{
            report_json: %{"affected" => "secret_pkg"},
            summary: "a bug",
            reporter_username: "somebody",
            maintainers: []
          },
          actor: Service.hexpm_intake()
        )

      drain()

      assert [%{to: [{_name, "emails_hex_report_poc@example.com"}]} = email] = sent_emails()
      assert email.text_body =~ "/cases/"
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

      case_record = Fixtures.open_case(poc)
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

      case_record = Fixtures.open_case(poc)
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

      case_record = Fixtures.open_case(poc)
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
      Cases.request_case_review!(Fixtures.open_case(poc), actor: other_poc)

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

      read_case = Fixtures.open_case(poc)
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

      case_record = Fixtures.open_case(poc)
      Cases.request_case_review!(case_record, actor: other_poc)

      # Run only the two fan-out jobs queued so far (the opener's own
      # assignment and the review request), so the row (and its
      # freshly-enqueued :email trigger job) exists while the user is still
      # in :immediate mode, without running that trigger job yet.
      # with_recursion must be off here or the newly-enqueued :email job
      # runs in the same call.
      drain(with_limit: 2, with_recursion: false)

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

      case_record = Fixtures.open_case(immediate_poc)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: digest_poc.id},
        actor: other_poc
      )

      Cases.request_case_review!(case_record, actor: other_poc)

      perform_job(Varsel.Notifications.Notification.EmailScheduler, %{})
      drain()

      emails = sent_emails()

      recipients =
        for {_name, addr} <- Enum.flat_map(emails, & &1.to), into: MapSet.new(), do: addr

      assert "emails_scheduler_immediate_poc@example.com" in recipients
      refute "emails_scheduler_digest_poc@example.com" in recipients

      assert [%Notification{emailed_at: %DateTime{}}] = notifications_for(immediate_poc)
      assert [_ | _] = digest_rows = notifications_for(digest_poc)
      assert Enum.all?(digest_rows, &is_nil(&1.emailed_at))
    end
  end

  describe "the HTML part" do
    alias Varsel.Cases.CaseInvite
    alias Varsel.Notifications.Emails

    @case_id "00000000-0000-4000-8000-000000000001"

    defp html(email), do: LazyHTML.from_document(email.html_body)

    defp hrefs(email) do
      email
      |> html()
      |> LazyHTML.query("a[href]")
      |> Enum.flat_map(&LazyHTML.attribute(&1, "href"))
    end

    test "an immediate email links the case and the settings, like its text part" do
      email =
        Emails.immediate_email(
          %Accounts.User{notification_email: "someone@example.com"},
          %Notification{kind: :comment_posted, case_id: @case_id}
        )

      links = hrefs(email)
      assert Enum.any?(links, &String.ends_with?(&1, "/cases/#{@case_id}"))
      assert Enum.any?(links, &String.ends_with?(&1, "/settings/notifications"))
      assert email |> html() |> LazyHTML.query("title") |> LazyHTML.text() == email.subject
    end

    test "a digest lists one row per kind with its count" do
      notifications =
        for kind <- [:comment_posted, :comment_posted, :case_published],
            do: %Notification{kind: kind, case_id: @case_id}

      email =
        Emails.digest_email(
          %Accounts.User{notification_email: "someone@example.com"},
          notifications
        )

      rows =
        email
        |> html()
        |> LazyHTML.query("tr")
        |> Enum.map(&(&1 |> LazyHTML.query("td") |> Enum.map(fn td -> LazyHTML.text(td) end)))

      assert ["1", "Case published"] in rows
      assert ["2", "New comment"] in rows
      assert Enum.any?(hrefs(email), &String.ends_with?(&1, "/notifications"))
    end

    test "an invite escapes the provider handle" do
      email =
        Emails.invite_email(%CaseInvite{
          email: "invitee@example.com",
          strategy: :github,
          username: "<img src=x onerror=alert(1)>",
          case_id: @case_id
        })

      doc = html(email)

      assert [] = doc |> LazyHTML.query("img[onerror]") |> Enum.to_list()
      assert doc |> LazyHTML.query(".handle") |> LazyHTML.text() == "<img src=x onerror=alert(1)>"

      assert Enum.any?(
               hrefs(email),
               &String.ends_with?(&1, "/sign-in?return_to=%2Fcases%2F#{@case_id}")
             )
    end

    test "a maintainer's invite escapes the handle and links the maintainer process" do
      email =
        Emails.invite_email(%CaseInvite{
          email: "invitee@example.com",
          strategy: :hex,
          username: "<img src=x onerror=alert(1)>",
          role: :maintainer,
          case_id: @case_id
        })

      doc = html(email)

      assert [] = doc |> LazyHTML.query("img[onerror]") |> Enum.to_list()
      assert doc |> LazyHTML.query(".handle") |> LazyHTML.text() == "<img src=x onerror=alert(1)>"

      links = hrefs(email)
      assert Enum.any?(links, &String.ends_with?(&1, "/sign-in?return_to=%2Fcases%2F#{@case_id}"))
      assert Enum.any?(links, &String.ends_with?(&1, "/maintainer-process"))
    end
  end

  describe "the invite text part" do
    alias Varsel.Cases.CaseInvite
    alias Varsel.Notifications.Emails

    defp invite_for(role) do
      Emails.invite_email(%CaseInvite{
        email: "invitee@example.com",
        strategy: :hex,
        username: "pkg_owner",
        role: role,
        case_id: "00000000-0000-4000-8000-000000000001"
      })
    end

    test "a maintainer's states the 14-day non-response policy" do
      email = invite_for(:maintainer)

      assert email.subject == "EEF CNA: review a possible vulnerability in your package"
      assert email.text_body =~ "within 14 days, we may publish the CVE without a fix"
      assert email.text_body =~ "/maintainer-process"
    end

    test "anyone else's states no deadline" do
      email = invite_for(:other)

      assert email.subject == "EEF CNA: join a vulnerability case"
      refute email.text_body =~ "14 days"
      assert email.text_body =~ "/maintainer-process"
    end
  end

  describe "the invite's account-linking hint" do
    alias Varsel.Cases.CaseInvite
    alias Varsel.Notifications.Emails

    test "names the other provider and links the account settings, in both parts" do
      for role <- [:maintainer, :other] do
        email =
          Emails.invite_email(%CaseInvite{
            email: "invitee@example.com",
            strategy: :github,
            username: "octocat",
            role: role,
            case_id: "00000000-0000-4000-8000-000000000001"
          })

        assert email.text_body =~
                 "Already signed up with hex.pm? Link GitHub to that account first:"

        assert email.text_body =~ "/settings/account\n"

        assert email.html_body
               |> LazyHTML.from_document()
               |> LazyHTML.query("a[href]")
               |> Enum.flat_map(&LazyHTML.attribute(&1, "href"))
               |> Enum.any?(&String.ends_with?(&1, "/settings/account"))
      end
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
