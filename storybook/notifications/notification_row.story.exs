# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Notifications.NotificationRow do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.NotificationComponents.notification_row/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :unread,
        description: "An unread row: the primary dot, and the toggle offers to mark it read.",
        attributes: %{
          notification: row(read_at: nil, count: 1, kind: :comment_posted, case: case_record())
        }
      },
      %Variation{
        id: :read,
        description: "A read row: no dot, no highlight, and the toggle offers to mark it unread.",
        attributes: %{
          notification: row(read_at: ago(3600), count: 1, kind: :case_published, case: case_record())
        }
      },
      %Variation{
        id: :absorbed_count,
        description: "Several unread events on the same subject absorb into one row: the ×N chip.",
        attributes: %{
          notification: row(read_at: nil, count: 4, kind: :proposal_opened, case: case_record())
        }
      },
      %Variation{
        id: :case_without_cve_id,
        description:
          "A case that has not been assigned a CVE ID yet: the headline still leads with the title, no chip beside it.",
        attributes: %{
          notification: row(read_at: nil, count: 1, kind: :review_requested, case: case_record(cve_id: nil))
        }
      },
      %Variation{
        id: :degraded_no_case,
        description:
          "A case-kind row whose case load came back nil: the viewer lost their assignment, or it is a report kind. Falls back to the kind label as the headline.",
        attributes: %{
          notification: row(read_at: nil, count: 1, kind: :comment_posted, case: nil)
        }
      },
      %Variation{
        id: :report_kind,
        description:
          ~s(A report-subject kind: no `case_id`, so both links read "Open triage queue" instead of "Open case".),
        attributes: %{
          notification: row(read_at: nil, count: 1, kind: :report_submitted, case_id: nil, case: nil)
        }
      }
    ]
  end

  defp ago(seconds), do: DateTime.shift(DateTime.utc_now(), second: -seconds)

  defp case_record(opts \\ []) do
    %{
      title: Keyword.get(opts, :title, "acme_lib leaks secrets in debug logs"),
      cve_id: Keyword.get(opts, :cve_id, "CVE-2026-12345")
    }
  end

  defp row(opts) do
    %{
      id: Ecto.UUID.generate(),
      kind: Keyword.fetch!(opts, :kind),
      count: Keyword.fetch!(opts, :count),
      last_event_at: ago(300),
      read_at: Keyword.get(opts, :read_at),
      case_id: Keyword.get(opts, :case_id, Ecto.UUID.generate()),
      case: Keyword.fetch!(opts, :case)
    }
  end
end
