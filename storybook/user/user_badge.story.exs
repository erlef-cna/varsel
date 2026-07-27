# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.User.UserBadge do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.UserComponents.user_badge/1

  def variations do
    [
      %Variation{
        id: :with_picture,
        description: "Picture and name together — how a user appears beside something they did.",
        attributes: %{
          user: %{name: "Jonatan Männchen", avatar_url: "https://github.com/maennchen.png"}
        }
      },
      %VariationGroup{
        id: :initials,
        description: """
        With no picture to reach, the disc falls back to initials. The two
        colour variants distinguish collaborators in one thread.
        """,
        variations: [
          %Variation{
            id: :variant_a,
            attributes: %{user: %{name: "Alex Rivera", avatar_url: nil}}
          },
          %Variation{
            id: :variant_b,
            attributes: %{user: %{name: "Sam Chen", avatar_url: nil}, variant: :b}
          }
        ]
      },
      %Variation{
        id: :deleted,
        description: """
        The account is gone: a muted dash in place of a picture, and a name
        that says so.
        """,
        attributes: %{user: nil}
      },
      %Variation{
        id: :truncated,
        description: "`name_class` is for the caller's layout — here, truncation in a narrow rail.",
        attributes: %{
          user: %{name: "A person with a very long name indeed", avatar_url: nil},
          name_class: "truncate max-w-[8rem]"
        }
      }
    ]
  end
end
