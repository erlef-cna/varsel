# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.NotificationBellLive do
  @moduledoc """
  Keeps the nav bell's unread count live, nested via `live_render/3` in
  `VarselWeb.Layouts.site_nav/1` so it works on controller-rendered pages too,
  not only inside another LiveView. `on_mount {VarselWeb.LiveUserAuth,
  :current_user}` resolves `current_user` from its own session.
  `VarselWeb.LiveNotifications` refetches the count on the user's broadcasts.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.NotificationComponents, only: [notification_bell: 1]

  alias Varsel.Notifications

  on_mount {VarselWeb.LiveUserAuth, :current_user}
  on_mount {VarselWeb.LiveNotifications, :default}

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    {:ok, assign_unread_count(socket, socket.assigns[:current_user])}
  end

  defp assign_unread_count(socket, %{id: user_id}) do
    keep_live(
      socket,
      :unread_notification_count,
      fn socket ->
        Notifications.unread_notification_count(actor: socket.assigns.current_user)
      end,
      subscribe: "notification:#{user_id}",
      results: :lose
    )
  end

  defp assign_unread_count(socket, nil), do: assign(socket, :unread_notification_count, nil)

  @impl Phoenix.LiveView
  def render(%{current_user: nil} = assigns), do: ~H""

  def render(assigns) do
    ~H"""
    <.notification_bell unread_count={@unread_notification_count} />
    """
  end
end
