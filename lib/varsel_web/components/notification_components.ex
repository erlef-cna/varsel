# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.NotificationComponents do
  @moduledoc """
  Components for the notification bell (`VarselWeb.Layouts.site_nav/1`) and
  the notifications page (`VarselWeb.NotificationsLive`).
  """

  use VarselWeb, :html

  import VarselWeb.CaseComponents, only: [relative_timestamp: 1]

  alias Varsel.Notifications.Kind

  @doc """
  The bell nav button: links to `/notifications`, with an unread-count badge
  when `unread_count` is a positive integer. `nil` (signed out) or `0` render
  the plain bell. The display count caps at "99+" so the badge never grows
  past the circle it sits in.
  """
  attr :unread_count, :integer, default: nil
  attr :class, :any, default: nil

  def notification_bell(assigns) do
    ~H"""
    <.link
      navigate={~p"/notifications"}
      class={["btn btn-ghost btn-sm btn-circle indicator text-white hover:bg-white/10", @class]}
      aria-label="Notifications"
    >
      <.icon name="hero-bell" class="size-5" />
      <span
        :if={is_integer(@unread_count) and @unread_count > 0}
        class="indicator-item badge badge-sm badge-info"
      >
        {badge_count(@unread_count)}
      </span>
    </.link>
    """
  end

  defp badge_count(count) when count > 99, do: "99+"
  defp badge_count(count), do: to_string(count)

  @doc """
  One row of the notifications list: headline linking to the subject,
  the kind underneath, an absorbed count chip when more than one event
  landed unread, a relative timestamp, an unread marker, the read/unread
  toggle and a second subject link labelled for what it opens.

  A case-kind row headlines the case's title and CVE ID, matching the case
  cards (`VarselWeb.BoardComponents.card/1`); `Kind.label/1` moves to the
  description line. `notification.case` comes back `nil` when the case
  load's own policy no longer lets the viewer see it (they lost their
  assignment) or for a report-kind row, and the row falls back to the kind
  label as its headline.
  """
  attr :notification, :any, required: true

  def notification_row(%{notification: %{case: %{} = case_record}} = assigns) do
    assigns = assign(assigns, :case, case_record)

    ~H"""
    <.row notification={@notification}>
      <div class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <.link navigate={subject_path(@notification)} class="link link-hover font-semibold">
          {@case.title || "Untitled"}
        </.link>
        <.mono_chip :if={@case.cve_id} size={:small}>{@case.cve_id}</.mono_chip>
        <.mono_chip :if={@notification.count > 1} size={:small}>
          {@notification.count}×
        </.mono_chip>
      </div>
      <p class="text-sm text-base-content/60">{Kind.label(@notification.kind)}</p>
    </.row>
    """
  end

  def notification_row(assigns) do
    ~H"""
    <.row notification={@notification}>
      <div class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <.link navigate={subject_path(@notification)} class="link link-hover font-semibold">
          {Kind.label(@notification.kind)}
        </.link>
        <.mono_chip :if={@notification.count > 1} size={:small}>
          {@notification.count}×
        </.mono_chip>
      </div>
      <p class="text-sm text-base-content/60">{Kind.description(@notification.kind)}</p>
    </.row>
    """
  end

  attr :notification, :any, required: true
  slot :inner_block, required: true

  defp row(assigns) do
    ~H"""
    <div class={[
      "flex items-start gap-3 px-4 py-3.5 border-b border-base-300 last:border-0",
      is_nil(@notification.read_at) && "bg-base-300/20"
    ]}>
      <span
        :if={is_nil(@notification.read_at)}
        class="badge badge-primary badge-xs mt-1.5 shrink-0"
        aria-label="Unread"
      ></span>

      <div class="min-w-0 flex-1">
        {render_slot(@inner_block)}
        <.relative_timestamp at={@notification.last_event_at} class="text-xs text-base-content/50" />
      </div>

      <div class="flex flex-col items-end gap-1 shrink-0">
        <button
          type="button"
          phx-click="toggle_read"
          phx-value-row_id={@notification.id}
          class="btn btn-ghost btn-xs"
        >
          {if is_nil(@notification.read_at), do: "Mark read", else: "Mark unread"}
        </button>
        <.link
          navigate={subject_path(@notification)}
          class="link link-hover text-xs text-base-content/50"
        >
          {subject_label(@notification)}
        </.link>
      </div>
    </div>
    """
  end

  @doc "Where a notification's `View` link goes: its case or its report."
  @spec subject_path(%{kind: Kind.t(), case_id: Ash.UUID.t() | nil}) :: String.t()
  def subject_path(%{case_id: case_id}) when not is_nil(case_id), do: ~p"/cases/#{case_id}"
  def subject_path(%{kind: :report_submitted}), do: ~p"/reports"
  def subject_path(_notification), do: ~p"/notifications"

  @doc "The subject-link label paired with `subject_path/1`."
  @spec subject_label(%{kind: Kind.t(), case_id: Ash.UUID.t() | nil}) :: String.t()
  def subject_label(%{case_id: case_id}) when not is_nil(case_id), do: "Open case →"
  def subject_label(%{kind: :report_submitted}), do: "Open triage queue →"
  def subject_label(_notification), do: "Open →"
end
