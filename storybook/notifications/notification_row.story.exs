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
        description: "An unread row: the primary dot and a bold headline. The toggle marks it read.",
        attributes: %{
          notification: row(read_at: nil, count: 1, kind: :comment_posted, case: case_record())
        }
      },
      %VariationGroup{
        id: :tones,
        description:
          "One row per kind, most important first. A review request and a suggestion are info blue, act the deeper amber, a mention red, addressed a lighter amber, activity neutral and done green.",
        variations:
          for kind <- VarselWeb.NotificationComponents.group_order() do
            %Variation{
              id: kind,
              attributes: %{
                notification: row(read_at: nil, count: 1, kind: kind, case: case_record())
              }
            }
          end
      },
      %Variation{
        id: :read,
        description: "A read row: no dot and a muted headline. The toggle marks it unread.",
        attributes: %{
          notification: row(read_at: ago(3600), count: 1, kind: :case_published, case: case_record())
        }
      },
      %Variation{
        id: :grouped,
        description:
          "In a list already grouped by kind (`show_kind?={false}`): the kind column drops, the group heading names it.",
        attributes: %{
          notification: row(read_at: nil, count: 1, kind: :comment_posted, case: case_record()),
          show_kind?: false
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
          "A row whose case load came back nil because the viewer lost their assignment: the row describes the kind instead.",
        attributes: %{
          notification: row(read_at: nil, count: 1, kind: :comment_posted, case: nil)
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
      case_id: Ecto.UUID.generate(),
      case: Keyword.fetch!(opts, :case)
    }
  end
end
