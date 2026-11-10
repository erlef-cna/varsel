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

  @group_order [
    :mentioned,
    :review_requested,
    :case_assigned,
    :report_submitted,
    :comment_posted,
    :proposal_opened,
    :case_published
  ]

  @doc """
  The notification kinds in the order the notifications page lists them:
  those addressed to the viewer first, then activity on their cases.
  """
  @spec group_order() :: [Kind.t()]
  def group_order, do: @group_order ++ (Kind.values() -- @group_order)

  @doc "A kind's name as a group of notifications."
  @spec group_label(Kind.t()) :: String.t()
  def group_label(:mentioned), do: "Mentions"
  def group_label(:review_requested), do: "Review requests"
  def group_label(:case_assigned), do: "Added to a case"
  def group_label(:report_submitted), do: "New reports"
  def group_label(:comment_posted), do: "Comments"
  def group_label(:proposal_opened), do: "Proposals"
  def group_label(:case_published), do: "Published"

  @doc "The icon that stands for a kind in the group rail."
  @spec group_icon(Kind.t()) :: String.t()
  def group_icon(:mentioned), do: "hero-at-symbol"
  def group_icon(:review_requested), do: "hero-clipboard-document-check"
  def group_icon(:case_assigned), do: "hero-user-plus"
  def group_icon(:report_submitted), do: "hero-inbox-arrow-down"
  def group_icon(:comment_posted), do: "hero-chat-bubble-left-right"
  def group_icon(:proposal_opened), do: "hero-pencil-square"
  def group_icon(:case_published), do: "hero-megaphone"

  @doc """
  The notifications page's group rail: one entry per kind in `groups`,
  under "For you" or "On your cases" by the kind's audience, each linking
  to its group with its unread count, or its total once everything in it
  is read.

  Groups are maps with `:kind`, `:total` and `:unread`. From `md` up the
  rail is a column; below it, a row that scrolls sideways.
  """
  attr :groups, :list, required: true
  attr :active, :atom, default: nil, doc: "the kind whose group is open"
  attr :class, :any, default: nil

  def notification_group_nav(assigns) do
    assigns =
      assign(assigns, :sections, [
        {"For you", Enum.reject(assigns.groups, &(Kind.audience(&1.kind) == :assigned))},
        {"On your cases", Enum.filter(assigns.groups, &(Kind.audience(&1.kind) == :assigned))}
      ])

    ~H"""
    <nav
      id="notification-groups"
      aria-label="Notification types"
      class={[
        "group-rail flex gap-1 overflow-x-auto pb-1 text-sm md:flex-col md:gap-4 md:overflow-visible md:pb-0",
        @class
      ]}
    >
      <div
        :for={{heading, groups} <- @sections}
        :if={groups != []}
        role="group"
        aria-label={heading}
        class="flex shrink-0 gap-1 md:flex-col md:gap-0.5"
      >
        <p
          aria-hidden="true"
          class="hidden px-2.5 pb-1 text-xs font-semibold text-base-content/60 md:block"
        >
          {heading}
        </p>
        <.link
          :for={group <- groups}
          id={"notification-group-#{group.kind}"}
          patch={~p"/notifications?#{[kind: group.kind]}"}
          aria-current={group.kind == @active && "page"}
          class={[
            "rail-link flex shrink-0 items-center gap-2 whitespace-nowrap rounded-[var(--radius-field)] px-2.5 py-3 md:py-1.5",
            "hover:bg-base-200 hover:text-base-content focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-primary",
            if(group.kind == @active,
              do: "is-active font-semibold",
              else: "text-base-content/75"
            )
          ]}
        >
          <.icon
            name={group_icon(group.kind)}
            class={[
              "size-4 shrink-0",
              if(group.kind == @active, do: "text-primary", else: "text-base-content/60")
            ]}
          />
          <span class="truncate">{group_label(group.kind)}</span>
          <span
            :if={group.unread > 0}
            class="ml-auto flex items-center gap-1.5 pl-1 text-xs font-bold tabular-nums text-base-content"
          >
            <span class="size-1.5 rounded-full bg-info" aria-hidden="true"></span>
            {badge_count(group.unread)}<span class="sr-only"> unread</span>
          </span>
          <span
            :if={group.unread == 0}
            class="ml-auto pl-1 text-xs tabular-nums text-base-content/60"
          >
            {group.total}<span class="sr-only"> read</span>
          </span>
        </.link>
      </div>
    </nav>
    """
  end

  @doc """
  One row of the notifications list: headline linking to the subject,
  the kind underneath, an absorbed count chip when more than one event
  landed unread, a relative timestamp, an unread marker, the read/unread
  toggle and a second subject link labelled for what it opens.

  A case-kind row headlines the case's title and CVE ID, matching the case
  cards (`VarselWeb.BoardComponents.card/1`); `Kind.label/1` moves to the
  description line, which `show_kind?={false}` drops for a list already
  grouped by kind. `notification.case` comes back `nil` when the case
  load's own policy no longer lets the viewer see it (they lost their
  assignment) or for a report-kind row, and the row falls back to the kind
  label as its headline.
  """
  attr :notification, :any, required: true
  attr :show_kind?, :boolean, default: true

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
      <p :if={@show_kind?} class="text-sm text-base-content/60">{Kind.label(@notification.kind)}</p>
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
        role="img"
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

  @doc """
  Where a notification's `View` link goes: its case, and a mention to the
  comments it was made in.
  """
  @spec subject_path(%{kind: Kind.t(), case_id: Ash.UUID.t()}) :: String.t()
  def subject_path(%{kind: :mentioned, case_id: case_id}), do: ~p"/cases/#{case_id}/comments"
  def subject_path(%{case_id: case_id}), do: ~p"/cases/#{case_id}"

  @doc "The subject-link label paired with `subject_path/1`."
  @spec subject_label(%{case_id: Ash.UUID.t()}) :: String.t()
  def subject_label(_notification), do: "Open case →"
end
