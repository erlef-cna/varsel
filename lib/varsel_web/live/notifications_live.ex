# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.NotificationsLive do
  @moduledoc """
  The signed-in user's own notifications, grouped by kind: a rail of the
  kinds they have, and the open kind's notifications most recent first, with
  a read/unread toggle per row and one action that marks every unread row
  read.

  Visiting the subject (`VarselWeb.CaseDetailLive`, `VarselWeb.ReportTriageLive`)
  is what marks a notification read; this page only lists and toggles.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]

  import VarselWeb.NotificationComponents,
    only: [notification_row: 1, notification_group_nav: 1, group_label: 1, group_order: 0]

  alias Varsel.Notifications
  alias Varsel.Notifications.Kind

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Notifications")
      |> keep_live(:summary, &summarize/1,
        subscribe: subscribe_topic(socket.assigns[:current_user]),
        results: :lose
      )

    {:ok, socket}
  end

  # An anonymous mount has no user id to scope a topic to; :read_notifications
  # is refused by policy before this subscription would ever matter.
  defp subscribe_topic(nil), do: []
  defp subscribe_topic(%{id: user_id}), do: "notification:#{user_id}"

  @impl Phoenix.LiveView
  def handle_params(params, _url, socket) do
    kind = selected_kind(params["kind"], socket.assigns.summary)

    {:noreply,
     socket
     |> assign(:kind, kind)
     |> keep_notifications_live()}
  end

  defp selected_kind(param, summary) do
    Enum.find(Kind.values(), &(Atom.to_string(&1) == param)) || default_kind(summary)
  end

  defp default_kind(summary) do
    Enum.find(group_order(), &(Map.get(summary.unread, &1, 0) > 0)) ||
      Enum.find(group_order(), &Map.has_key?(summary.total, &1))
  end

  # Both assigns share the user's topic, and the LiveNotifications hook
  # refetches every assign on a topic from one subscription, so the topic is
  # dropped before keep_live subscribes it again for the newly opened group.
  defp keep_notifications_live(socket) do
    topic = subscribe_topic(socket.assigns[:current_user])
    if is_binary(topic), do: socket.endpoint.unsubscribe(topic)

    keep_live(socket, :notifications, &list_notifications/2, subscribe: topic, results: :lose)
  end

  @impl Phoenix.LiveView
  def handle_event("paginate", %{"page" => target}, socket) do
    {:noreply, change_page(socket, :notifications, target)}
  end

  def handle_event("jump_page", %{"page" => target}, socket) do
    {:noreply, jump_to_page(socket, :notifications, target)}
  end

  def handle_event("toggle_read", %{"row_id" => id}, socket) do
    actor = socket.assigns.current_user
    notification = Enum.find(page_results(socket.assigns.notifications), &(&1.id == id))

    socket =
      case toggle(notification, actor) do
        {:ok, _notification} -> socket
        {:error, _error} -> put_flash(socket, :error, "Could not update that notification.")
      end

    {:noreply, socket}
  end

  def handle_event("mark_all_read", _params, socket) do
    socket =
      case Notifications.mark_all_notifications_read(actor: socket.assigns.current_user) do
        %Ash.BulkResult{status: :success} -> socket
        %Ash.BulkResult{} -> put_flash(socket, :error, "Could not mark your notifications read.")
      end

    {:noreply, socket}
  end

  defp toggle(nil, _actor), do: {:error, :not_found}

  defp toggle(%{read_at: nil} = notification, actor),
    do: Notifications.mark_notification_read(notification, %{}, actor: actor)

  defp toggle(notification, actor), do: Notifications.mark_notification_unread(notification, %{}, actor: actor)

  # Counts per kind across every notification the user has, for the rail and
  # the header, plus one unread row for the mark-all affordance to ask about.
  defp summarize(socket) do
    rows =
      Notifications.read_notifications!(
        actor: socket.assigns.current_user,
        query: [select: [:id, :kind, :read_at, :user_id]]
      )

    unread = Enum.filter(rows, &is_nil(&1.read_at))

    %{
      total: Enum.frequencies_by(rows, & &1.kind),
      unread: Enum.frequencies_by(unread, & &1.kind),
      unread_row: List.first(unread)
    }
  end

  # The keep_live callback: page_opts is nil on the first run and the stored
  # page's options on a refetch, so a toggle keeps the page the user is on.
  # The case load runs under Case's own read policy as the same actor, so a
  # user no longer assigned gets `case: nil` back rather than an error —
  # notification_row/1 falls back to the kind label alone for that row.
  defp list_notifications(%{assigns: %{kind: nil}}, _page_opts), do: nil

  defp list_notifications(socket, page_opts) do
    Notifications.list_notifications!(
      actor: socket.assigns.current_user,
      query: [filter: [kind: socket.assigns.kind]],
      page: page_opts || [count: true, offset: 0],
      load: [case: [:title, :cve_id]]
    )
  end

  # The group heading already counts what is in it, so the footer only
  # appears when there is another page to reach.
  defp pageable?(nil), do: false

  defp pageable?(page) do
    case AshPhoenix.LiveView.last_page(page) do
      :unknown -> true
      last_page -> last_page > 1
    end
  end

  defp page_results(nil), do: []
  defp page_results(page), do: page.results

  # The open group stays in the rail even with nothing in it, so a link to an
  # emptied group still shows where the reader is.
  defp groups(summary, active) do
    for kind <- group_order(), kind == active or Map.has_key?(summary.total, kind) do
      %{
        kind: kind,
        total: Map.get(summary.total, kind, 0),
        unread: Map.get(summary.unread, kind, 0)
      }
    end
  end

  defp unread_total(summary), do: summary.unread |> Map.values() |> Enum.sum()

  # A record-less update cannot answer a row-filter policy, so the question
  # is asked about one unread row.
  defp can_mark_all_read?(%{unread_row: nil}, _actor), do: false

  defp can_mark_all_read?(%{unread_row: row}, actor), do: Notifications.can_mark_notification_read?(actor, row)

  defp unread_headline(0), do: "Nothing unread"
  defp unread_headline(1), do: "1 unread"
  defp unread_headline(count), do: "#{count} unread"

  defp group_tally(0, total), do: "#{total} read"
  defp group_tally(unread, total), do: "#{unread} unread · #{total} total"

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
        <:subtitle>{unread_headline(unread_total(@summary))}</:subtitle>
        <:actions :if={can_mark_all_read?(@summary, @current_user)}>
          <button
            type="button"
            id="mark-all-read"
            class="btn btn-sm btn-eef-quiet"
            phx-click="mark_all_read"
          >
            Mark all read
          </button>
        </:actions>
      </.page_header>

      <.page_container>
        <%= if @kind do %>
          <div class="md:grid md:grid-cols-[14rem_minmax(0,1fr)] md:items-start md:gap-8">
            <.notification_group_nav
              groups={groups(@summary, @kind)}
              active={@kind}
              class="mb-5 md:sticky md:top-24 md:mb-0"
            />

            <section
              id="notification-group"
              aria-labelledby="notification-group-title"
              class="min-w-0"
            >
              <div class="mb-3 flex flex-wrap items-end justify-between gap-x-4 gap-y-1">
                <div class="min-w-0">
                  <h2 id="notification-group-title" class="text-lg font-semibold leading-tight">
                    {group_label(@kind)}
                  </h2>
                  <p class="text-sm text-base-content/60">{Kind.description(@kind)}</p>
                </div>
                <p
                  :if={Map.has_key?(@summary.total, @kind)}
                  class="text-xs tabular-nums text-base-content/60"
                >
                  {group_tally(Map.get(@summary.unread, @kind, 0), @summary.total[@kind])}
                </p>
              </div>

              <.list_card empty?={page_results(@notifications) == []}>
                <:empty>Nothing here yet.</:empty>
                <:footer :if={pageable?(@notifications)}>
                  <.pagination page={@notifications} noun="notification" />
                </:footer>

                <.notification_row
                  :for={notification <- page_results(@notifications)}
                  notification={notification}
                  show_kind?={false}
                />
              </.list_card>
            </section>
          </div>
        <% else %>
          <.list_card empty?>
            <:empty>Nothing to see yet.</:empty>
          </.list_card>
        <% end %>
      </.page_container>
    </Layouts.app>
    """
  end
end
