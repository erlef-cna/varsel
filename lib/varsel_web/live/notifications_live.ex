# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.NotificationsLive do
  @moduledoc """
  The signed-in user's own notifications: every kind, most recent first, with
  a read/unread toggle per row.

  Visiting the subject (`VarselWeb.CaseDetailLive`, `VarselWeb.ReportTriageLive`)
  is what marks a notification read; this page only lists and toggles.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]
  import VarselWeb.NotificationComponents, only: [notification_row: 1]

  alias Varsel.Notifications

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Notifications")
      |> keep_live(:notifications, &list_notifications/2,
        subscribe: subscribe_topic(socket.assigns[:current_user]),
        results: :lose
      )

    {:ok, socket}
  end

  # An anonymous mount has no user id to scope a topic to; :list_notifications
  # is refused by policy before this subscription would ever matter.
  defp subscribe_topic(nil), do: []
  defp subscribe_topic(%{id: user_id}), do: "notification:#{user_id}"

  @impl Phoenix.LiveView
  def handle_event("paginate", %{"page" => target}, socket) do
    {:noreply, change_page(socket, :notifications, target)}
  end

  def handle_event("jump_page", %{"page" => target}, socket) do
    {:noreply, jump_to_page(socket, :notifications, target)}
  end

  def handle_event("toggle_read", %{"row_id" => id}, socket) do
    actor = socket.assigns.current_user
    notification = Enum.find(socket.assigns.notifications.results, &(&1.id == id))

    socket =
      case toggle(notification, actor) do
        {:ok, _notification} -> socket
        {:error, _error} -> put_flash(socket, :error, "Could not update that notification.")
      end

    {:noreply, socket}
  end

  defp toggle(nil, _actor), do: {:error, :not_found}

  defp toggle(%{read_at: nil} = notification, actor),
    do: Notifications.mark_notification_read(notification, %{}, actor: actor)

  defp toggle(notification, actor), do: Notifications.mark_notification_unread(notification, %{}, actor: actor)

  # The keep_live callback: page_opts is nil on the first run and the stored
  # page's options on a refetch, so a toggle keeps the page the user is on.
  # The case load runs under Case's own read policy as the same actor, so a
  # user no longer assigned gets `case: nil` back rather than an error —
  # notification_row/1 falls back to the kind label alone for that row.
  defp list_notifications(socket, page_opts) do
    Notifications.list_notifications!(
      actor: socket.assigns.current_user,
      page: page_opts || [count: true, offset: 0],
      load: [case: [:title, :cve_id]]
    )
  end

  defp unread_count(notifications) do
    Enum.count(notifications.results, &is_nil(&1.read_at))
  end

  defp unread_headline(0), do: "Nothing unread"
  defp unread_headline(1), do: "1 unread"
  defp unread_headline(count), do: "#{count} unread"

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.app
      flash={@flash}
      current_user={@current_user}
      current_path={@current_path}
      socket={@socket}
    >
      <.page_header>
        <:eyebrow>CNA Console</:eyebrow>
        <:title>Notifications</:title>
        <:subtitle>{unread_headline(unread_count(@notifications))}</:subtitle>
      </.page_header>

      <.page_container>
        <.list_card empty?={@notifications.results == []}>
          <:empty>Nothing to see yet.</:empty>
          <:footer :if={paged?(@notifications)}>
            <.pagination page={@notifications} noun="notification" />
          </:footer>

          <.notification_row
            :for={notification <- @notifications.results}
            notification={notification}
          />
        </.list_card>
      </.page_container>
    </Layouts.app>
    """
  end
end
