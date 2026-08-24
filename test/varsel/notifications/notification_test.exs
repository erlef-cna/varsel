# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.NotificationTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Varsel.Fixtures
  alias Varsel.Notifications
  alias Varsel.Notifications.Notification

  setup do
    poc = Fixtures.register_user("notif_poc", :poc)
    other = Fixtures.register_user("notif_other", :supporter)
    case_record = Fixtures.open_case(poc)
    %{poc: poc, other: other, case: case_record}
  end

  describe "record" do
    test "absorbs a repeated event into one unread row and bumps count", %{
      poc: poc,
      case: case_record
    } do
      notification =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      assert notification.count == 1
      first_event_at = notification.last_event_at

      absorbed =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      assert absorbed.id == notification.id
      assert absorbed.count == 2
      assert DateTime.after?(absorbed.last_event_at, first_event_at)

      assert [%Notification{id: id, count: 2}] = Ash.read!(Notification, actor: poc)

      assert id == notification.id
    end

    test "a different kind on the same case starts a separate row", %{
      poc: poc,
      case: case_record
    } do
      Notifications.record_notification!(
        %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
        authorize?: false
      )

      Notifications.record_notification!(
        %{kind: :proposal_opened, user_id: poc.id, case_id: case_record.id},
        authorize?: false
      )

      rows = Ash.read!(Notification, actor: poc)
      assert length(rows) == 2
      assert rows |> Enum.map(& &1.kind) |> Enum.sort() == [:comment_posted, :proposal_opened]
    end

    test "the same kind on a different case starts a separate row", %{poc: poc, case: case_record} do
      other_case = Fixtures.open_case(poc)

      Notifications.record_notification!(
        %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
        authorize?: false
      )

      Notifications.record_notification!(
        %{kind: :comment_posted, user_id: poc.id, case_id: other_case.id},
        authorize?: false
      )

      rows = Ash.read!(Notification, actor: poc)
      assert length(rows) == 2
    end

    test "after mark_read a further record starts a second row, and the read row keeps its count",
         %{
           poc: poc,
           case: case_record
         } do
      Notifications.record_notification!(
        %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
        authorize?: false
      )

      first =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      read = Notifications.mark_notification_read!(first, actor: poc)
      assert read.count == 2
      assert read.read_at

      second =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      assert second.id != first.id
      assert second.count == 1

      rows = Ash.read!(Notification, actor: poc)
      assert length(rows) == 2

      reloaded_first = Enum.find(rows, &(&1.id == first.id))
      assert reloaded_first.count == 2
    end

    test "dedups with a nil case_id against a vulnerability_report_id subject", %{poc: poc} do
      report = report_fixture(poc)

      Notifications.record_notification!(
        %{kind: :report_submitted, user_id: poc.id, vulnerability_report_id: report.id},
        authorize?: false
      )

      absorbed =
        Notifications.record_notification!(
          %{kind: :report_submitted, user_id: poc.id, vulnerability_report_id: report.id},
          authorize?: false
        )

      assert absorbed.count == 2
      assert [%Notification{}] = Ash.read!(Notification, actor: poc)
    end
  end

  describe "policies" do
    test "an anonymous actor cannot list notifications" do
      assert {:error, %Forbidden{}} = Notifications.list_notifications(actor: nil)
    end

    test "another user sees no rows", %{poc: poc, other: other, case: case_record} do
      Notifications.record_notification!(
        %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
        authorize?: false
      )

      assert [] = Notifications.list_notifications!(actor: other)
    end

    test "the owner sees their own rows", %{poc: poc, case: case_record} do
      notification =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      assert [%Notification{id: id}] = Notifications.list_notifications!(actor: poc)
      assert id == notification.id
    end

    test "the owner's rows can be paginated", %{poc: poc, case: case_record} do
      other_case = Fixtures.open_case(poc)

      Notifications.record_notification!(
        %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
        authorize?: false
      )

      Notifications.record_notification!(
        %{kind: :comment_posted, user_id: poc.id, case_id: other_case.id},
        authorize?: false
      )

      assert %Ash.Page.Offset{results: [%Notification{}], more?: true, count: 2} =
               Notifications.list_notifications!(
                 actor: poc,
                 page: [limit: 1, offset: 0, count: true]
               )
    end

    test "another user cannot mark a notification read", %{
      poc: poc,
      other: other,
      case: case_record
    } do
      notification =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      assert {:error, %Forbidden{}} =
               Notifications.mark_notification_read(notification, actor: other)
    end

    test "another user cannot mark a notification unread", %{
      poc: poc,
      other: other,
      case: case_record
    } do
      notification =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      read = Notifications.mark_notification_read!(notification, actor: poc)

      assert {:error, %Forbidden{}} =
               Notifications.mark_notification_unread(read, actor: other)
    end

    test "record is forbidden even for an authorized actor", %{poc: poc, case: case_record} do
      assert {:error, %Forbidden{}} =
               Notifications.record_notification(
                 %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
                 actor: poc
               )
    end

    test "Ash.can? denies :record and :mark_emailed to a POC", %{poc: poc} do
      refute Ash.can?({Notification, :record}, poc)
      refute Ash.can?({Notification, :mark_emailed}, poc)
    end
  end

  describe "unread_notification_count" do
    test "drops after mark_read and rises again after mark_unread", %{
      poc: poc,
      case: case_record
    } do
      notification =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      assert Notifications.unread_notification_count(actor: poc) == 1

      read = Notifications.mark_notification_read!(notification, actor: poc)
      assert Notifications.unread_notification_count(actor: poc) == 0

      Notifications.mark_notification_unread!(read, actor: poc)
      assert Notifications.unread_notification_count(actor: poc) == 1
    end
  end

  describe "mark_case_notifications_read" do
    test "marks only the actor's unread rows for that case, leaving another user's untouched", %{
      poc: poc,
      other: other,
      case: case_record
    } do
      poc_notification =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      other_notification =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: other.id, case_id: case_record.id},
          authorize?: false
        )

      assert %Ash.BulkResult{status: :success} =
               Notifications.mark_case_notifications_read(case_record.id, actor: poc)

      reloaded_poc = Ash.get!(Notification, poc_notification.id, authorize?: false)
      reloaded_other = Ash.get!(Notification, other_notification.id, authorize?: false)

      assert reloaded_poc.read_at
      assert is_nil(reloaded_other.read_at)
    end
  end

  describe "mark_kind_notifications_read" do
    test "marks only the actor's unread rows of that kind, leaving another kind and another user untouched",
         %{poc: poc, other: other, case: case_record} do
      report_submitted =
        Notifications.record_notification!(
          %{
            kind: :report_submitted,
            user_id: poc.id,
            vulnerability_report_id: report_fixture(poc).id
          },
          authorize?: false
        )

      comment_posted =
        Notifications.record_notification!(
          %{kind: :comment_posted, user_id: poc.id, case_id: case_record.id},
          authorize?: false
        )

      other_report_submitted =
        Notifications.record_notification!(
          %{
            kind: :report_submitted,
            user_id: other.id,
            vulnerability_report_id: report_fixture(other).id
          },
          authorize?: false
        )

      assert %Ash.BulkResult{status: :success} =
               Notifications.mark_kind_notifications_read(:report_submitted, actor: poc)

      assert Ash.get!(Notification, report_submitted.id, authorize?: false).read_at
      assert is_nil(Ash.get!(Notification, comment_posted.id, authorize?: false).read_at)
      assert is_nil(Ash.get!(Notification, other_report_submitted.id, authorize?: false).read_at)
    end
  end

  defp report_fixture(poc) do
    Varsel.CVE.submit_vulnerability_report!(
      %{
        report_json: %{"x" => 1},
        summary: "a bug",
        confirms_criteria: true,
        confirms_in_scope: true
      },
      actor: poc
    )
  end
end
