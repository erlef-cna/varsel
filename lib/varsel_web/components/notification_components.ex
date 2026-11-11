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
    :review_requested,
    :report_submitted,
    :mentioned,
    :case_assigned,
    :proposal_opened,
    :comment_posted,
    :case_published
  ]

  @doc """
  The notification kinds in the order the notifications page lists them,
  most important first: what waits on the viewer, what is addressed to
  them, then activity on their cases.
  """
  @spec group_order() :: [Kind.t()]
  def group_order, do: @group_order ++ (Kind.values() -- @group_order)

  @doc "A kind's name as a group of notifications, or `:all` for every kind."
  @spec group_label(Kind.t() | :all) :: String.t()
  def group_label(:all), do: "All"
  def group_label(:mentioned), do: "Mentions"
  def group_label(:review_requested), do: "Review requests"
  def group_label(:case_assigned), do: "Added to a case"
  def group_label(:report_submitted), do: "New reports"
  def group_label(:comment_posted), do: "Comments"
  def group_label(:proposal_opened), do: "Proposals"
  def group_label(:case_published), do: "Published"

  @doc """
  How much a kind asks of the viewer, which sets the colour of its icon:

    * `:review`: a case waits on their review
    * `:act`: a new report waits to be triaged
    * `:mention`: someone asked them something in a comment
    * `:addressed`: it adds them to a case
    * `:suggestion`: a proposal awaiting a decision
    * `:activity`: conversation on their cases
    * `:done`: an outcome to know about
  """
  @spec kind_tone(Kind.t()) ::
          :review | :act | :mention | :addressed | :suggestion | :activity | :done
  def kind_tone(:review_requested), do: :review
  def kind_tone(:report_submitted), do: :act
  def kind_tone(:mentioned), do: :mention
  def kind_tone(:case_assigned), do: :addressed
  def kind_tone(:proposal_opened), do: :suggestion
  def kind_tone(:comment_posted), do: :activity
  def kind_tone(:case_published), do: :done

  @doc "The icon that stands for a kind, or `:all`, in the group rail."
  @spec group_icon(Kind.t() | :all) :: String.t()
  def group_icon(:all), do: "hero-inbox-stack"
  def group_icon(:mentioned), do: "hero-at-symbol"
  def group_icon(:review_requested), do: "hero-clipboard-document-check"
  def group_icon(:case_assigned), do: "hero-user-plus"
  def group_icon(:report_submitted), do: "hero-inbox-arrow-down"
  def group_icon(:comment_posted), do: "hero-chat-bubble-left-right"
  def group_icon(:proposal_opened), do: "hero-pencil-square"
  def group_icon(:case_published), do: "hero-megaphone"

  @doc """
  The notifications page's group rail: an "All" entry over every kind, then
  one entry per kind in `groups`, under "For you" or "On your cases" by the
  kind's audience. Each links to its group with its unread count, or its
  total once everything in it is read.

  Groups are maps with `:kind`, `:total` and `:unread`. From `md` up the
  rail is a column; below it, a row that scrolls sideways.
  """
  attr :groups, :list, required: true
  attr :active, :atom, default: nil, doc: "the kind whose group is open, or `:all`"
  attr :class, :any, default: nil

  def notification_group_nav(assigns) do
    groups = assigns.groups

    assigns =
      assign(assigns,
        all: %{
          kind: :all,
          total: groups |> Enum.map(& &1.total) |> Enum.sum(),
          unread: groups |> Enum.map(& &1.unread) |> Enum.sum()
        },
        sections: [
          {"For you", Enum.filter(groups, &addressed_to_viewer?(&1.kind))},
          {"On your cases", Enum.reject(groups, &addressed_to_viewer?(&1.kind))}
        ]
      )

    ~H"""
    <nav
      id="notification-groups"
      aria-label="Notification types"
      class={[
        "group-rail flex gap-1 overflow-x-auto pb-1 text-sm md:flex-col md:gap-4 md:overflow-visible md:pb-0",
        @class
      ]}
    >
      <div class="flex shrink-0 md:flex-col">
        <.rail_link group={@all} active={@active} />
      </div>
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
        <.rail_link :for={group <- groups} group={group} active={@active} />
      </div>
    </nav>
    """
  end

  attr :group, :map, required: true
  attr :active, :atom, default: nil

  defp rail_link(assigns) do
    ~H"""
    <.link
      id={"notification-group-#{@group.kind}"}
      patch={group_path(@group.kind)}
      aria-current={@group.kind == @active && "page"}
      class={[
        "rail-link relative flex shrink-0 items-center gap-2 whitespace-nowrap rounded-[var(--radius-field)] px-2.5 py-3 md:py-1.5",
        "hover:bg-base-200 hover:text-base-content focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-primary",
        if(@group.kind == @active,
          do: "is-active font-semibold",
          else: "text-base-content/75"
        )
      ]}
    >
      <.icon
        name={group_icon(@group.kind)}
        class={[
          "size-4 shrink-0",
          if(@group.kind == @active, do: "text-primary", else: "text-base-content/60")
        ]}
      />
      <span class="truncate">{group_label(@group.kind)}</span>
      <span
        :if={@group.unread > 0}
        class="ml-auto flex items-center gap-1.5 pl-1 text-xs font-bold tabular-nums text-base-content"
      >
        <span class="size-1.5 rounded-full bg-info" aria-hidden="true"></span>
        {badge_count(@group.unread)}<span class="sr-only"> unread</span>
      </span>
      <span
        :if={@group.unread == 0}
        class="ml-auto pl-1 text-xs tabular-nums text-base-content/60"
      >
        {@group.total}<span class="sr-only"> read</span>
      </span>
    </.link>
    """
  end

  defp group_path(:all), do: ~p"/notifications"
  defp group_path(kind), do: ~p"/notifications?#{[kind: kind]}"

  @doc """
  One row of the notifications list, which opens the subject anywhere it is
  clicked: an unread dot, the kind as an icon and label, the headline with
  an absorbed count chip when more than one event landed unread, the
  relative time and a read/unread toggle.

  The kind leads in a column of its own, its icon coloured by
  `kind_tone/1`.
  `show_kind?={false}` drops it for a list already grouped by kind.

  A row headlines the case's title and CVE ID, matching the case cards
  (`VarselWeb.BoardComponents.card/1`). `notification.case` comes back
  `nil` when the case load's own policy no longer lets the viewer see it
  (they lost their assignment), and the row describes the kind instead.
  """
  attr :notification, :any, required: true
  attr :show_kind?, :boolean, default: true

  def notification_row(%{notification: %{case: %{} = case_record}} = assigns) do
    assigns = assign(assigns, :case, case_record)

    ~H"""
    <.row
      notification={@notification}
      show_kind?={@show_kind?}
      headline={@case.title || "Untitled"}
    >
      <:chips :if={@case.cve_id}>
        <.mono_chip size={:small}>{@case.cve_id}</.mono_chip>
      </:chips>
    </.row>
    """
  end

  def notification_row(assigns) do
    ~H"""
    <.row
      notification={@notification}
      show_kind?={@show_kind?}
      headline={Kind.description(@notification.kind)}
    />
    """
  end

  attr :notification, :any, required: true
  attr :show_kind?, :boolean, required: true
  attr :headline, :string, required: true
  slot :chips

  defp row(assigns) do
    assigns =
      assign(assigns,
        unread?: is_nil(assigns.notification.read_at),
        kind: assigns.notification.kind
      )

    ~H"""
    <div class={[
      "relative flex items-center gap-3 px-4 py-2.5 border-b border-base-300 last:border-0",
      "hover:bg-base-300/40 has-[a:focus-visible]:outline-2 has-[a:focus-visible]:-outline-offset-2 has-[a:focus-visible]:outline-primary"
    ]}>
      <span
        class={["size-2 shrink-0 rounded-full", @unread? && "bg-primary"]}
        role={@unread? && "img"}
        aria-label={@unread? && "Unread"}
      ></span>

      <div :if={@show_kind?} class="flex shrink-0 items-center gap-2.5 md:w-48">
        <span class={[
          "grid size-7 shrink-0 place-items-center rounded-[var(--radius-field)]",
          "notice-tone-#{kind_tone(@kind)}"
        ]}>
          <.icon name={group_icon(@kind)} class="size-4" />
        </span>
        <span class="hidden truncate text-sm text-base-content/80 md:block">
          {Kind.label(@kind)}
        </span>
      </div>

      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <.link
            navigate={subject_path(@notification)}
            class={[
              "line-clamp-2 break-words text-sm after:absolute after:inset-0 focus-visible:outline-none",
              if(@unread?, do: "font-semibold", else: "text-base-content/75")
            ]}
          >
            {@headline}
          </.link>
          {render_slot(@chips)}
          <.mono_chip :if={@notification.count > 1} size={:small}>
            {@notification.count}×
          </.mono_chip>
        </div>
        <p class="truncate text-xs text-base-content/60 md:hidden">
          <span :if={@show_kind?}>{Kind.label(@kind)} ·</span>
          <.relative_timestamp at={@notification.last_event_at} class="tabular-nums" />
        </p>
      </div>

      <.relative_timestamp
        at={@notification.last_event_at}
        class="hidden shrink-0 whitespace-nowrap text-xs tabular-nums text-base-content/60 md:block"
      />

      <button
        type="button"
        phx-click="toggle_read"
        phx-value-row_id={@notification.id}
        title={toggle_label(@unread?)}
        class="btn btn-ghost btn-sm btn-square relative z-10 shrink-0 text-base-content/60 hover:text-base-content"
      >
        <.icon name={toggle_icon(@unread?)} class="size-5" />
        <span class="sr-only">{toggle_label(@unread?)}</span>
      </button>
    </div>
    """
  end

  defp addressed_to_viewer?(kind), do: Kind.audience(kind) != :assigned

  defp toggle_label(true), do: "Mark read"
  defp toggle_label(false), do: "Mark unread"

  defp toggle_icon(true), do: "hero-envelope-open"
  defp toggle_icon(false), do: "hero-envelope"

  @doc """
  Where a notification row leads: its case, and a mention to the
  comments it was made in.
  """
  @spec subject_path(%{kind: Kind.t(), case_id: Ash.UUID.t()}) :: String.t()
  def subject_path(%{kind: :mentioned, case_id: case_id}), do: ~p"/cases/#{case_id}/comments"
  def subject_path(%{case_id: case_id}), do: ~p"/cases/#{case_id}"
end
