# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Notifications.NotificationBell do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.NotificationComponents.notification_bell/1

  def layout, do: :one_column

  def description do
    "Lives in the navy nav band's `ml-auto` group, next to the theme toggle. Shown here on the band it belongs to."
  end

  def template do
    """
    <div class="eef-band p-6 rounded-box flex justify-center">
      <.psb-variation/>
    </div>
    """
  end

  def variations do
    [
      %Variation{
        id: :none,
        description: "Signed out, or nothing unread — the plain bell, no badge.",
        attributes: %{unread_count: nil}
      },
      %Variation{
        id: :few,
        description: "A handful unread.",
        attributes: %{unread_count: 3}
      },
      %Variation{
        id: :ninety_nine_plus,
        description: "The badge caps its display at 99+, staying inside the circle.",
        attributes: %{unread_count: 140}
      }
    ]
  end
end
