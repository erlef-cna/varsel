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
        description: """
        Signed out: public links only, plus the sign-in affordance. In dev the
        mock-login menu appears beside it (compiled out everywhere else).
        """,
        attributes: %{current_path: "/"}
      },
      %Variation{
        id: :supporter,
        description: "A signed-in supporter also sees Cases and Reports.",
        attributes: %{
          current_path: "/cases",
          current_user: %{name: "Alex Rivera", email: "alex@example.com", role: :supporter}
        }
      },
      %Variation{
        id: :poc,
        description: "A POC additionally sees Users.",
        attributes: %{
          current_path: "/users",
          current_user: %{name: "Sam Chen", email: "sam@example.com", role: :poc}
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
          current_user: %{name: "Alex Rivera", email: "alex@example.com", role: :supporter}
        }
      },
      %Variation{
        id: :no_name,
        description: "Without a name the account menu falls back to the email.",
        attributes: %{
          current_path: "/cases",
          current_user: %{name: nil, email: "reporter@example.com", role: :supporter}
        }
      }
    ]
  end
end
