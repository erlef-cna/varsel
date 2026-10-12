# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.User.UserPicker do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.UserComponents.user_picker/1

  @users [
    %{
      id: "poc",
      role: :poc,
      display_name: "Jonatan Männchen",
      avatar_url: "https://github.com/maennchen.png",
      github_username: "maennchen",
      hex_username: "maennchen"
    },
    %{
      id: "supporter",
      role: :supporter,
      display_name: "Alex Rivera",
      avatar_url: nil,
      github_username: "arivera",
      hex_username: nil
    },
    %{
      id: "member",
      role: nil,
      display_name: "sam_chen",
      avatar_url: nil,
      github_username: nil,
      hex_username: "sam_chen"
    }
  ]

  def variations do
    [
      %Variation{
        id: :untyped,
        description: """
        Before anything is typed: the accounts the viewer may see, points of
        contact and supporters first. Handles sit at the row's end, the role
        beside the name when the viewer may read it.
        """,
        attributes: %{query: "", users: @users}
      },
      %Variation{
        id: :selected,
        description: "A chosen row stays checked across a re-render.",
        attributes: %{query: "", users: @users, selected: "supporter"}
      },
      %Variation{
        id: :cut,
        description: "More accounts matched than the caller listed, so the picker asks for more letters.",
        attributes: %{query: "a", users: @users, more?: true}
      },
      %Variation{
        id: :no_match,
        description: "Nothing matched the query.",
        attributes: %{query: "zzz", users: []}
      },
      %Variation{
        id: :role_hidden,
        description: """
        A viewer who may not read roles sees them as a forbidden field, which
        renders as no chip at all.
        """,
        attributes: %{
          query: "",
          users: [
            %{List.first(@users) | role: %Ash.ForbiddenField{field: :role, type: :attribute}}
          ]
        }
      }
    ]
  end
end
