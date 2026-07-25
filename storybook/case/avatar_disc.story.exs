# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.AvatarDisc do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.avatar_disc/1

  def variations do
    [
      %VariationGroup{
        id: :initials,
        description: """
        Without a GitHub handle the disc falls back to two initials. The two
        colour variants distinguish collaborators in a thread.
        """,
        variations: [
          %Variation{id: :variant_a, attributes: %{user: %{name: "Alex Rivera"}}},
          %Variation{id: :variant_b, attributes: %{user: %{name: "Sam Chen"}, variant: :b}},
          %Variation{
            id: :single_name,
            attributes: %{user: %{name: "Varsel"}}
          },
          %Variation{
            id: :email_only,
            description: "No name at all renders \"?\".",
            attributes: %{user: %{email: "reporter@example.com"}}
          }
        ]
      },
      %Variation{
        id: :github_avatar,
        description: """
        With a handle on record the disc uses the GitHub avatar. Users
        authenticate through GitHub, so that is the only avatar source there is.
        """,
        attributes: %{user: %{name: "Jonatan Männchen", github_handle: "maennchen"}}
      },
      %Variation{
        id: :sized_up,
        description: "`class` overrides the default 21px disc.",
        attributes: %{user: %{name: "Alex Rivera"}, class: "size-10 text-base"}
      }
    ]
  end
end
