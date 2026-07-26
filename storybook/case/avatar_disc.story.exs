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
        With no picture to show — no linked GitHub account and no address to
        key a Gravatar on — the disc falls back to two initials. The two colour
        variants distinguish collaborators in a thread.
        """,
        variations: [
          %Variation{
            id: :variant_a,
            attributes: %{user: %{name: "Alex Rivera", avatar_url: nil}}
          },
          %Variation{
            id: :variant_b,
            attributes: %{user: %{name: "Sam Chen", avatar_url: nil}, variant: :b}
          },
          %Variation{
            id: :single_name,
            attributes: %{user: %{name: "Varsel", avatar_url: nil}}
          },
          %Variation{
            id: :no_name,
            description: "No name at all renders \"?\".",
            attributes: %{user: %{avatar_url: nil}}
          }
        ]
      },
      %Variation{
        id: :github_avatar,
        description: """
        A linked GitHub account is the best picture we have, so `:avatar_url`
        resolves to its profile image.
        """,
        attributes: %{
          user: %{
            name: "Jonatan Männchen",
            avatar_url: "https://github.com/maennchen.png"
          }
        }
      },
      %Variation{
        id: :gravatar,
        description: """
        Without GitHub it falls back to Gravatar on the notification address —
        what hex.pm itself does, since hex publishes no avatar. `d=mp` renders
        a neutral silhouette when the address has none.
        """,
        attributes: %{
          user: %{
            name: "Sam Chen",
            avatar_url: "https://www.gravatar.com/avatar/4feb46d146a8ffe7bf72672525916af5?d=mp"
          }
        }
      },
      %Variation{
        id: :sized_up,
        description: "`class` overrides the default 21px disc.",
        attributes: %{user: %{name: "Alex Rivera", avatar_url: nil}, class: "size-10 text-base"}
      }
    ]
  end
end
