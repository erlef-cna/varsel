# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.NotificationsLive do
  @moduledoc """
  The signed-in user's own notifications, most recent first, all of them or
  one kind at a time from a rail of the kinds they have, with a read/unread
  toggle per row and one action that marks every unread row read.

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
    {:ok, assign(socket, :page_title, "Notifications")}
  end

  # An anonymous mount has no user id to scope a topic to; :read_notifications
  # is refused by policy before this subscription would ever matter.
  defp subscribe_topic(nil), do: []
  defp subscribe_topic(%{id: user_id}), do: "notification:#{user_id}"

  @impl Phoenix.LiveView
  def handle_params(params, _url, socket) do
    {:noreply,
     socket
     |> assign(:kind, selected_kind(params["kind"]))
     |> keep_notifications_live()}
  end

  defp selected_kind(param), do: Enum.find(Kind.values(), :all, &(Atom.to_string(&1) == param))

  # A patch to another group re-runs keep_live, so the topic is dropped first
  # rather than subscribed twice. The rail's counts span every kind, and
  # refresh with each fetch of the open group.
  defp keep_notifications_live(socket) do
    topic = subscribe_topic(socket.assigns[:current_user])
    if is_binary(topic), do: socket.endpoint.unsubscribe(topic)

    keep_live(socket, :notifications, &list_notifications/2,
      subscribe: topic,
      results: :lose,
      after_fetch: fn _page, socket -> assign(socket, :summary, summarize(socket)) end
    )
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
    notification = Enum.find(socket.assigns.notifications.results, &(&1.id == id))

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
      total_count: length(rows),
      unread_count: length(unread),
      unread_row: List.first(unread)
    }
  end

  # The keep_live callback: page_opts is nil on the first run and the stored
  # page's options on a refetch, so a toggle keeps the page the user is on.
  # The case load runs under Case's own read policy as the same actor, so a
  # user no longer assigned gets `case: nil` back rather than an error —
  # notification_row/1 describes the kind instead for that row.
  defp list_notifications(socket, page_opts) do
    Notifications.list_notifications!(
      actor: socket.assigns.current_user,
      query: [filter: kind_filter(socket.assigns.kind)],
      page: page_opts || [count: true, offset: 0],
      load: [case: [:title, :cve_id]]
    )
  end

  defp kind_filter(:all), do: []
  defp kind_filter(kind), do: [kind: kind]

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

  defp group_counts(summary, :all), do: {summary.unread_count, summary.total_count}

  defp group_counts(summary, kind), do: {Map.get(summary.unread, kind, 0), Map.get(summary.total, kind, 0)}

  defp group_description(:all), do: "Every notification you have, most recent first."
  defp group_description(kind), do: Kind.description(kind)

  # A record-less update cannot answer a row-filter policy, so the question
  # is asked about one unread row.
  defp can_mark_all_read?(%{unread_row: nil}, _actor), do: false

  defp can_mark_all_read?(%{unread_row: row}, actor), do: Notifications.can_mark_notification_read?(actor, row)

  defp unread_headline(0), do: "Nothing unread"
  defp unread_headline(1), do: "1 unread"
  defp unread_headline(count), do: "#{count} unread"

  defp group_tally({0, total}), do: "#{total} read"
  defp group_tally({unread, total}), do: "#{unread} unread · #{total} total"

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
        <:subtitle>{unread_headline(@summary.unread_count)}</:subtitle>
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
        <%= if @kind != :all or @summary.total != %{} do %>
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
                  <p class="text-sm text-base-content/60">{group_description(@kind)}</p>
                </div>
                <p
                  :if={elem(group_counts(@summary, @kind), 1) > 0}
                  class="text-xs tabular-nums text-base-content/60"
                >
                  {group_tally(group_counts(@summary, @kind))}
                </p>
              </div>

              <.list_card empty?={@notifications.results == []}>
                <:empty>Nothing here yet.</:empty>
                <:footer :if={pageable?(@notifications)}>
                  <.pagination page={@notifications} noun="notification" />
                </:footer>

                <.notification_row
                  :for={notification <- @notifications.results}
                  notification={notification}
                  show_kind?={@kind == :all}
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
