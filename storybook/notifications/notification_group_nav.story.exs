# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Notifications.NotificationGroupNav do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.NotificationComponents.notification_group_nav/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full max-w-60"}

  def variations do
    [
      %Variation{
        id: :all,
        description: "The default view: All, over every kind, is open and sums their counts above both sections.",
        attributes: %{
          active: :all,
          groups: [
            group(:mentioned, 3, 2),
            group(:case_assigned, 4, 0),
            group(:comment_posted, 18, 5)
          ]
        }
      },
      %Variation{
        id: :mixed,
        description:
          "Both sections: unread groups carry an info dot and count, fully read groups their muted total. The open group is marked.",
        attributes: %{
          active: :mentioned,
          groups: [
            group(:mentioned, 3, 2),
            group(:review_requested, 1, 1),
            group(:case_assigned, 4, 0),
            group(:comment_posted, 18, 5),
            group(:proposal_opened, 7, 0),
            group(:case_published, 2, 0)
          ]
        }
      },
      %Variation{
        id: :activity_only,
        description: "Only activity on the viewer's cases: the \"For you\" section drops out.",
        attributes: %{
          active: :proposal_opened,
          groups: [group(:comment_posted, 4, 0), group(:proposal_opened, 2, 2)]
        }
      },
      %Variation{
        id: :overflowing_count,
        description: "An unread count past 99 caps at 99+, like the bell.",
        attributes: %{
          active: :comment_posted,
          groups: [group(:report_submitted, 140, 120), group(:comment_posted, 12, 0)]
        }
      }
    ]
  end

  defp group(kind, total, unread), do: %{kind: kind, total: total, unread: unread}
end
