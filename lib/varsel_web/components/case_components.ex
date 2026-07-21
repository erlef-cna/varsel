# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseComponents do
  @moduledoc """
  Components of the case workspace: the lifecycle stepper, the section rail
  with readiness markers, the unified activity feed, and rendered case
  markdown.
  """

  use Phoenix.Component

  import Phoenix.HTML, only: [raw: 1]

  alias Varsel.Cases.Markdown

  @lifecycle [draft: "Draft", review: "Review", approved: "Approved", published: "Published"]

  @doc """
  Renders the case lifecycle as a stepper: done steps ✓, the current step
  filled, upcoming steps hollow. `:publishing` renders as the Published step
  in progress; a closed case shows a terminal pill instead of a pipeline.
  """
  attr :state, :atom, required: true

  def lifecycle_stepper(%{state: :closed} = assigns) do
    ~H"""
    <div class="flex items-center gap-2 mt-2 text-sm text-base-content/60">
      <span class="badge badge-neutral badge-sm">Closed</span> terminal — reopen to continue
    </div>
    """
  end

  def lifecycle_stepper(assigns) do
    assigns = assign(assigns, :steps, lifecycle_steps(assigns.state))

    ~H"""
    <div class="flex items-center mt-2.5">
      <%= for {{label, status}, index} <- Enum.with_index(@steps) do %>
        <div :if={index > 0} class={["w-8 h-0.5 mx-2", stepper_line_class(status)]}></div>
        <span class={["flex items-center gap-1.5 text-xs font-semibold", stepper_text_class(status)]}>
          <span class={[
            "size-[18px] rounded-full border-2 inline-flex items-center justify-center text-[0.6rem]",
            stepper_dot_class(status)
          ]}>
            {if status == :done, do: "✓", else: index + 1}
          </span>
          {label}
        </span>
      <% end %>
    </div>
    """
  end

  defp lifecycle_steps(state) do
    current = lifecycle_index(state)

    @lifecycle
    |> Enum.with_index(1)
    |> Enum.map(fn {{step, label}, index} ->
      label = if step == :published and state == :publishing, do: "Publishing…", else: label

      cond do
        state == :published -> {label, :done}
        index < current -> {label, :done}
        index == current -> {label, :current}
        true -> {label, :todo}
      end
    end)
  end

  defp lifecycle_index(:draft), do: 1
  defp lifecycle_index(:review), do: 2
  defp lifecycle_index(:approved), do: 3
  defp lifecycle_index(:publishing), do: 4
  defp lifecycle_index(_published_or_other), do: 4

  defp stepper_line_class(:todo), do: "bg-base-300"
  defp stepper_line_class(_done_or_current), do: "bg-success/50"

  defp stepper_text_class(:done), do: "text-base-content/60"
  defp stepper_text_class(:current), do: "text-base-content"
  defp stepper_text_class(:todo), do: "text-base-content/40"

  defp stepper_dot_class(:done), do: "border-success text-success"
  defp stepper_dot_class(:current), do: "border-primary bg-primary text-primary-content"
  defp stepper_dot_class(:todo), do: "border-base-300 text-base-content/40"

  @doc """
  The workspace's section rail: anchor links with a readiness marker
  (✓ ready, ● needs work) or an open-suggestion count (◆ n) on the right.
  Sections are maps with `:id`, `:label`, `:status` and optional
  `:suggestions`.

  The SectionRail hook owns the interaction: it scrolls anchor clicks
  (LiveView's history bookkeeping breaks native smooth fragment scrolling)
  and marks the entry nearest the viewport top with `.is-active`.
  """
  attr :sections, :list, required: true
  attr :id, :string, default: "section-rail"
  attr :class, :any, default: nil

  def section_nav(assigns) do
    ~H"""
    <nav id={@id} phx-hook="SectionRail" class={["text-sm", @class]}>
      <a
        :for={section <- @sections}
        href={"##{section.id}"}
        class="rail-link flex items-center gap-2 rounded-[var(--radius-field)] px-2.5 py-1.5 text-base-content/70 hover:bg-base-200 hover:text-base-content"
      >
        <span class="truncate">{section.label}</span>
        <span
          :if={Map.get(section, :suggestions, 0) > 0}
          class="ml-auto text-info text-xs font-bold tabular-nums"
          title="Open suggestions"
        >
          ◆ {section.suggestions}
        </span>
        <span
          :if={Map.get(section, :suggestions, 0) == 0 and section.status == :ok}
          class="ml-auto text-success text-xs"
          title="Ready"
        >
          ✓
        </span>
        <span
          :if={Map.get(section, :suggestions, 0) == 0 and section.status == :attention}
          class="ml-auto text-warning text-xs"
          title="Needs work"
        >
          ●
        </span>
      </a>
    </nav>
    """
  end

  @doc """
  The unified activity feed: comments, suggestions and other case events
  interleaved, newest first. Entries are maps with `:kind`
  (:comment | :proposal | :event), `:who`, `:at`, `:body` and `:markdown?`.
  """
  attr :entries, :list, required: true

  def activity_feed(assigns) do
    ~H"""
    <ol class="text-sm">
      <li
        :for={entry <- @entries}
        class="relative border-l-2 border-base-300 ml-1 pl-4 pb-4 last:pb-0"
      >
        <span class={[
          "absolute -left-[5px] top-1.5 size-2 rounded-full",
          feed_dot_class(entry.kind)
        ]}></span>
        <p class="text-xs text-base-content/60">
          <span class="font-semibold text-base-content/90">{entry.who}</span>
          · {Calendar.strftime(entry.at, "%Y-%m-%d %H:%M")}
        </p>
        <.markdown :if={entry[:markdown?]} content={entry.body} class="prose-xs" />
        <p :if={!entry[:markdown?]} class="text-base-content/70">{entry.body}</p>
      </li>
    </ol>
    <p :if={@entries == []} class="text-sm text-base-content/60">Nothing yet.</p>
    """
  end

  defp feed_dot_class(:comment), do: "bg-primary"
  defp feed_dot_class(:proposal), do: "bg-info"
  defp feed_dot_class(_event), do: "bg-success"

  @doc """
  Renders a suggestion's change as an old → new diff: the current value
  struck through on a red tint, the suggested value on a green tint. Either
  side may be absent (pure additions/removals).
  """
  attr :old, :string, default: nil
  attr :new, :string, default: nil

  def suggestion_diff(assigns) do
    ~H"""
    <div class="rounded-md border border-base-300 overflow-hidden text-sm">
      <%!-- phx-no-format: pre-wrap would render the formatter's indentation --%>
      <div
        :if={@old not in [nil, ""]}
        class="px-2.5 py-1 bg-error/10 text-error/80 line-through decoration-error/40 whitespace-pre-wrap break-words"
        phx-no-format
      >{@old}</div>
      <div
        :if={@new not in [nil, ""]}
        class="px-2.5 py-1 bg-success/10 text-success whitespace-pre-wrap break-words"
        phx-no-format
      >{@new}</div>
    </div>
    """
  end

  @doc "Renders case markdown (mdex, raw HTML escaped) with prose styling."
  attr :content, :string, required: true
  attr :class, :any, default: nil

  def markdown(assigns) do
    ~H"""
    <div class={["prose prose-sm max-w-none", @class]}>{raw(Markdown.to_html(@content))}</div>
    """
  end

  @doc """
  A severity chip: rating word and score in one chip, severity-colored text
  on a tinted (never solid) background with a small radius.
  """
  attr :severity, :atom, required: true
  attr :score, :any, required: true

  def severity_chip(assigns) do
    ~H"""
    <span class={[
      "inline-flex items-center gap-1.5 rounded-[var(--radius-selector)] px-2.5 py-0.5",
      "text-[0.8rem] font-bold uppercase tabular-nums whitespace-nowrap",
      severity_chip_class(@severity)
    ]}>
      {@severity} {format_score(@score)}
    </span>
    """
  end

  defp severity_chip_class(:low), do: "text-success bg-success/15"
  defp severity_chip_class(:medium), do: "text-warning bg-warning/15"
  defp severity_chip_class(:high), do: "text-error bg-error/15"
  defp severity_chip_class(:critical), do: "text-error bg-error/15"
  defp severity_chip_class(_none_or_unknown), do: "text-base-content/60 bg-base-300/60"

  defp format_score(score) when is_number(score), do: :erlang.float_to_binary(score / 1, decimals: 1)

  defp format_score(score), do: to_string(score)

  @doc """
  Pretty-prints a JSON-shaped term (string-keyed maps, lists, scalars) with
  simple syntax tinting: keys in primary, strings in success, numbers in
  warning. Values are HTML-escaped; the result is safe to interpolate.
  """
  @spec json_highlight(term()) :: Phoenix.HTML.safe()
  def json_highlight(value), do: {:safe, json_frag(value, "")}

  defp json_frag(map, _indent) when map == %{}, do: "{}"

  defp json_frag(map, indent) when is_map(map) do
    inner = indent <> "  "

    entries =
      map
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map_intersperse(",\n", fn {key, value} ->
        [
          inner,
          ~s(<span class="text-primary">),
          escape(Jason.encode!(to_string(key))),
          "</span>: ",
          json_frag(value, inner)
        ]
      end)

    ["{\n", entries, "\n", indent, "}"]
  end

  defp json_frag([], _indent), do: "[]"

  defp json_frag(list, indent) when is_list(list) do
    inner = indent <> "  "
    entries = Enum.map_intersperse(list, ",\n", &[inner, json_frag(&1, inner)])
    ["[\n", entries, "\n", indent, "]"]
  end

  defp json_frag(value, _indent) when is_binary(value) do
    [~s(<span class="text-success">), escape(Jason.encode!(value)), "</span>"]
  end

  defp json_frag(value, _indent) when is_number(value) do
    [~s(<span class="text-warning">), Jason.encode!(value), "</span>"]
  end

  defp json_frag(value, _indent), do: escape(Jason.encode!(value))

  defp escape(binary) do
    {:safe, iodata} = Phoenix.HTML.html_escape(binary)
    iodata
  end
end
