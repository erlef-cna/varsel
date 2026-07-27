# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Layout.SiteNav do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.Layouts.site_nav/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :anonymous,
        description: "Signed out: public links only, plus the sign-in affordance.",
        attributes: %{current_path: "/"}
      },
      %Variation{
        id: :supporter,
        description: "A signed-in supporter also sees Cases and Reports.",
        attributes: %{
          current_path: "/cases",
          current_user: %{
            name: "Alex Rivera",
            display_name: "Alex Rivera",
            avatar_url: nil,
            role: :supporter
          }
        }
      },
      %Variation{
        id: :poc,
        description: "A POC additionally sees Users.",
        attributes: %{
          current_path: "/users",
          current_user: %{name: "Sam Chen", display_name: "Sam Chen", avatar_url: nil, role: :poc}
        }
      },
      %Variation{
        id: :active_link,
        description: """
        The most specific owner of the current path is highlighted — so
        `/settings/tokens` does not light up an unrelated section.
        """,
        attributes: %{
          current_path: "/common-weaknesses",
          current_user: %{
            name: "Alex Rivera",
            display_name: "Alex Rivera",
            avatar_url: nil,
            role: :supporter
          }
        }
      },
      %Variation{
        id: :no_name,
        description: """
        Nobody set a name, so both the menu label and the initials disc fall
        back to the provider handle `display_name` carries.
        """,
        attributes: %{
          current_path: "/cases",
          current_user: %{name: nil, display_name: "reporter", avatar_url: nil, role: :supporter}
        }
      }
    ]
  end
end
