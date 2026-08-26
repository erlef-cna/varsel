# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.User.UserName do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.UserComponents.user_name/1

  def variations do
    [
      %Variation{
        id: :named,
        description: "The name the account goes by.",
        attributes: %{user: %{name: "Alex Rivera"}}
      },
      %Variation{
        id: :no_name_set,
        description: """
        The provider reported no name, so `display_name` falls back to the
        handle the account signed in with.
        """,
        attributes: %{user: %{name: nil, display_name: "alexrivera"}}
      },
      %Variation{
        id: :hidden,
        description: """
        Neither name field reached the component, so there is nothing to show.
        """,
        attributes: %{user: %{}}
      },
      %Variation{
        id: :deleted,
        description: """
        The account is gone. Its comments, proposals and reports stay behind,
        so this is an ordinary thing to render rather than an error — and it
        reads differently from a name merely withheld.
        """,
        attributes: %{user: nil}
      }
    ]
  end
end
