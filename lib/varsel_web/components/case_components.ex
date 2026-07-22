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

  alias Phoenix.LiveView.JS
  alias Varsel.Cases.Markdown
  alias Varsel.Cases.WordDiff

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
        class={[
          "rail-link flex items-center gap-2 rounded-[var(--radius-field)] px-2.5 py-1.5 text-base-content/70 hover:bg-base-200 hover:text-base-content",
          section.id == "suggestions" && "mt-2 border-t border-base-300 pt-2.5"
        ]}
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
          <span class="text-base-content/50">· {relative_time(entry.at)}</span>
        </p>
        <.markdown :if={entry[:markdown?]} content={entry.body} class="prose-xs" />
        <p :if={!entry[:markdown?]} class="text-base-content/70">
          {entry.body}<span
            :if={entry[:chip]}
            class="font-mono text-[11px] bg-base-300 rounded px-1 py-px mx-1"
          >{entry.chip}</span>{entry[:suffix]}
        </p>
      </li>
    </ol>
    <p :if={@entries == []} class="text-sm text-base-content/60">Nothing yet.</p>
    """
  end

  # Comments are the warm hue; the palette's only non-status warm is amber.
  defp feed_dot_class(:comment), do: "bg-warning"
  defp feed_dot_class(:proposal), do: "bg-info"
  defp feed_dot_class(:state), do: "bg-success"
  defp feed_dot_class(_system_or_other), do: "bg-base-content/30"

  @doc """
  Renders a relative timestamp ("just now" / "5m ago" / "2h ago" / "3d ago"),
  falling back to an absolute date past 7 days; the full datetime always sits
  in the `title` attribute.
  """
  attr :at, :any, required: true
  attr :class, :any, default: nil

  def relative_timestamp(assigns) do
    ~H"""
    <span class={@class} title={Calendar.strftime(@at, "%Y-%m-%d %H:%M UTC")}>
      {relative_time(@at)}
    </span>
    """
  end

  @doc "The text used by `relative_timestamp/1`; exposed for inline composition."
  @spec relative_time(DateTime.t()) :: String.t()
  def relative_time(%DateTime{} = at) do
    seconds = DateTime.diff(DateTime.utc_now(), at, :second)

    cond do
      seconds < 60 -> "just now"
      seconds < 3600 -> "#{div(seconds, 60)}m ago"
      seconds < 86_400 -> "#{div(seconds, 3600)}h ago"
      seconds < 7 * 86_400 -> "#{div(seconds, 86_400)}d ago"
      true -> Calendar.strftime(at, "%b %-d, %Y")
    end
  end

  @doc """
  Renders a suggestion's change as an old → new diff over the raw field
  value (never markdown-rendered — what's being accepted is the raw
  text). When both sides are plain strings similar enough to merge
  (`Varsel.Cases.WordDiff`), renders one neutral body with removed words
  struck red and added words green, folding runs of untouched paragraphs
  behind a client-side toggle. Otherwise falls back to the stacked
  old-then-new blocks (pure additions/removals, dissimilar rewrites, and
  non-prose values all take this path). Either side may be absent (pure
  additions/removals always stack). Stacked slash-delimited single tokens
  (CVSS vectors) additionally emphasize their changed `/`-segments inside
  the rows (`WordDiff.stacked_highlight/2`).
  """
  attr :old, :string, default: nil
  attr :new, :string, default: nil

  def suggestion_diff(assigns) do
    result = word_diff_result(assigns.old, assigns.new)

    highlight =
      if result == :stacked,
        do: WordDiff.stacked_highlight(assigns.old, assigns.new),
        else: :plain

    assigns = assign(assigns, result: result, highlight: highlight)

    ~H"""
    <div class="rounded-md border border-base-300 overflow-hidden text-sm">
      <.merged_diff_body :if={match?({:merged, _paragraphs}, @result)} paragraphs={elem(@result, 1)} />
      <%!-- phx-no-format: pre-wrap would render the formatter's indentation --%>
      <%= if @result == :stacked do %>
        <div
          :if={@old not in [nil, ""]}
          class="px-2.5 py-1 bg-error/10 text-error/80 line-through decoration-error/40 whitespace-pre-wrap break-words"
          phx-no-format
        ><%= if @highlight == :plain do %>{@old}<% else %><.stacked_segments segments={elem(@highlight, 1)} /><% end %></div>
        <div
          :if={@new not in [nil, ""]}
          class="px-2.5 py-1 bg-success/10 text-success whitespace-pre-wrap break-words"
          phx-no-format
        ><%= if @highlight == :plain do %>{@new}<% else %><.stacked_segments segments={elem(@highlight, 2)} /><% end %></div>
      <% end %>
    </div>
    """
  end

  defp word_diff_result(old, new) when is_binary(old) and is_binary(new), do: WordDiff.diff(old, new)

  defp word_diff_result(_old, _new), do: :stacked

  attr :segments, :list, required: true

  # Slash-value emphasis inside an already-tinted stacked row (CVSS
  # vectors): changed segments get a stronger patch of the row's own tint
  # so the one changed metric stands out of the near-identical pair.
  defp stacked_segments(assigns) do
    ~H"""
    <span :for={{kind, text} <- @segments} class={stacked_segment_class(kind)}>{text}</span>
    """
  end

  defp stacked_segment_class(:eq), do: nil
  defp stacked_segment_class(:del), do: "rounded-[3px] px-0.5 box-decoration-clone bg-error/25"
  defp stacked_segment_class(:ins), do: "rounded-[3px] px-0.5 box-decoration-clone bg-success/25"

  attr :paragraphs, :list, required: true

  defp merged_diff_body(assigns) do
    assigns = assign(assigns, :rows, fold_rows(assigns.paragraphs))

    ~H"""
    <%= for row <- @rows do %>
      <div
        :if={row.kind == :paragraph}
        class="px-2.5 py-1 whitespace-pre-wrap break-words text-base-content"
        phx-no-format
      ><.diff_segments segments={row.segments} /></div>

      <div :if={row.kind == :fold} id={row.id}>
        <button
          type="button"
          class="w-full border-y border-base-300/60 bg-base-content/2 px-2.5 py-1 text-left text-xs text-base-content/50 cursor-pointer select-none"
          phx-click={JS.toggle(to: "##{row.id}-content")}
        >
          <span class="font-mono">⋯</span> {row.count} unchanged paragraph{if row.count > 1, do: "s"}
        </button>
        <div
          id={"#{row.id}-content"}
          class="hidden px-2.5 py-1 whitespace-pre-wrap break-words text-base-content/70"
          phx-no-format
        >
          <.diff_segments :for={segments <- row.paragraphs} segments={segments} />
        </div>
      </div>
    <% end %>
    """
  end

  attr :segments, :list, required: true

  defp diff_segments(assigns) do
    ~H"""
    <span :for={{kind, text} <- @segments} class={diff_segment_class(kind)}>{text}</span>
    """
  end

  defp diff_segment_class(:eq), do: nil

  defp diff_segment_class(:del),
    do: "rounded-[3px] px-0.5 box-decoration-clone bg-error/15 text-error/85 line-through decoration-error/45"

  defp diff_segment_class(:ins), do: "rounded-[3px] px-0.5 box-decoration-clone bg-success/15 text-success"

  # Folds runs of unchanged paragraphs into a single toggle row when the
  # run is >= 2 long or touches the start/end (edge context is pure cost —
  # fold even a single one); a lone unchanged paragraph strictly between
  # two changed ones renders in place instead, since folding it saves one
  # paragraph and costs a click.
  defp fold_rows(paragraphs) do
    chunks = Enum.chunk_by(paragraphs, &elem(&1, 0))
    last_index = length(chunks) - 1

    chunks
    |> Enum.with_index()
    |> Enum.flat_map(fn {chunk, index} -> fold_chunk(chunk, index, last_index) end)
  end

  defp fold_chunk([{:changed, _} | _] = chunk, _index, _last_index) do
    Enum.map(chunk, fn {:changed, segments} -> %{kind: :paragraph, segments: segments} end)
  end

  defp fold_chunk([{:unchanged, _} | _] = chunk, index, last_index) do
    edge? = index == 0 or index == last_index

    if length(chunk) >= 2 or edge? do
      [fold_row(chunk)]
    else
      Enum.map(chunk, fn {:unchanged, segments} -> %{kind: :paragraph, segments: segments} end)
    end
  end

  defp fold_row(chunk) do
    %{
      kind: :fold,
      id: "fold-#{System.unique_integer([:positive])}",
      count: length(chunk),
      paragraphs: Enum.map(chunk, fn {:unchanged, segments} -> segments end)
    }
  end

  @doc """
  Renders a user identity as a small filled circle: their GitHub avatar when
  a handle is on record, otherwise a 2-letter initials disc. Users
  authenticate via GitHub, so the handle is the only avatar source we have.
  """
  attr :user, :any, required: true
  attr :variant, :atom, default: :a, values: [:a, :b], doc: "the mock's two avatar color variants"
  attr :class, :any, default: nil

  def avatar_disc(assigns) do
    ~H"""
    <img
      :if={Map.get(@user, :github_handle)}
      src={"https://github.com/#{@user.github_handle}.png"}
      alt=""
      class={["size-[21px] shrink-0 rounded-full object-cover", @class]}
    />
    <span
      :if={!Map.get(@user, :github_handle)}
      class={[
        "inline-flex size-[21px] shrink-0 items-center justify-center rounded-full text-[0.6rem] font-bold",
        avatar_variant_class(@variant),
        @class
      ]}
    >
      {initials(@user)}
    </span>
    """
  end

  defp avatar_variant_class(:a), do: "bg-primary text-primary-content"
  defp avatar_variant_class(:b), do: "bg-secondary text-secondary-content"

  @doc """
  Renders an open (or resolved) suggestion inline, inside the section card it
  targets: author identity + field chip + timestamp, the old→new diff,
  reasoning, and an action row (Accept/Decline/Withdraw + a reply count that
  expands the proposal's comment thread). `id` anchors the rail's "Jump" link.
  """
  attr :id, :string, required: true
  attr :proposal, :any, required: true
  attr :old, :string, default: nil
  attr :new, :string, default: nil
  attr :can_resolve, :boolean, default: false
  attr :own, :boolean, default: false
  attr :comments, :list, default: []
  slot :inner_block, doc: "raw payload for non-:set operations (insert/delete)"

  def suggestion_card(assigns) do
    ~H"""
    <div id={@id} class="rounded-lg border border-info/40 bg-info/5 p-3 text-sm scroll-mt-4">
      <div class="flex items-center gap-2">
        <.avatar_disc user={@proposal.author} variant={:b} />
        <span class="font-bold">{display_name(@proposal.author)}</span>
        <span class="text-base-content/70">suggests</span>
        <span class="badge badge-sm badge-info badge-outline font-mono">
          {suggestion_target_field(@proposal)}
        </span>
        <.relative_timestamp
          at={@proposal.inserted_at}
          class="ml-auto shrink-0 text-xs text-base-content/50"
        />
      </div>

      <.suggestion_diff :if={@proposal.operation == :set} old={@old} new={@new} />
      {render_slot(@inner_block)}

      <div :if={@proposal.reasoning} class="mt-2 text-base-content/80">
        <.markdown content={@proposal.reasoning} class="prose-xs" />
      </div>

      <div class="mt-2 flex items-center gap-2">
        <form
          :if={@proposal.state == :open and @can_resolve}
          phx-submit="resolve_proposal"
          id={"resolve-#{@proposal.id}"}
          class="flex items-center gap-1.5"
        >
          <input type="hidden" name="proposal_id" value={@proposal.id} />
          <button type="submit" name="decision" value="accept" class="btn btn-primary btn-xs">
            Accept
          </button>
          <.decline_control proposal_id={@proposal.id} />
        </form>
        <button
          :if={@proposal.state == :open and @own}
          class="link link-hover text-xs text-base-content/60"
          phx-click="withdraw_proposal"
          phx-value-id={@proposal.id}
        >
          Withdraw
        </button>
        <button
          :if={@comments != []}
          class="link link-hover ml-auto shrink-0 text-xs text-base-content/50"
          phx-click={JS.toggle(to: "#suggestion-#{@proposal.id}-thread")}
        >
          {length(@comments)} {if length(@comments) == 1, do: "reply", else: "replies"}
        </button>
      </div>

      <div id={"suggestion-#{@proposal.id}-thread"} class="hidden mt-2 border-t border-info/20 pt-2">
        <.activity_feed entries={
          Enum.map(@comments, fn comment ->
            %{
              kind: :comment,
              who: display_name(comment.author),
              at: comment.inserted_at,
              body: comment.body,
              markdown?: true
            }
          end)
        } />
      </div>
    </div>
    """
  end

  # A small filled-circle initials disc; the "b" variant (violet) distinguishes
  # a second collaborator per the mock, applied by whichever caller decides.
  defp initials(%{name: name}) when is_binary(name) and name != "" do
    name
    |> String.split(~r/\s+/, trim: true)
    |> Enum.map(&String.first/1)
    |> Enum.take(2)
    |> Enum.join()
    |> String.upcase()
  end

  defp initials(_user), do: "?"

  defp suggestion_target_field(%{operation: :set, target: :case, field_name: field}), do: "case.#{field}"

  defp suggestion_target_field(%{operation: :set, target: target, field_name: field}) do
    "#{target}.#{field}"
  end

  defp suggestion_target_field(%{operation: :insert, target: target}), do: "+ #{target}"
  defp suggestion_target_field(%{operation: :delete, target: target}), do: "− #{target}"

  defp display_name(%{name: name}) when is_binary(name) and name != "", do: name
  defp display_name(%{email: email}) when is_binary(email), do: email
  defp display_name(_user), do: "(hidden)"

  # Decline requires a click before it offers the note input/confirm button —
  # not a permanently visible input. Plain JS show/hide; no server round trip
  # is needed to reveal a text field.
  attr :proposal_id, :string, required: true

  defp decline_control(assigns) do
    ~H"""
    <span id={"decline-#{@proposal_id}"} class="inline-flex items-center gap-1.5">
      <button
        type="button"
        class="btn btn-ghost btn-xs"
        phx-click={
          JS.hide(to: "#decline-#{@proposal_id} [data-decline-toggle]")
          |> JS.show(to: "#decline-#{@proposal_id} [data-decline-note]", display: "inline-block")
          |> JS.show(to: "#decline-#{@proposal_id} [data-decline-submit]", display: "inline-flex")
        }
        data-decline-toggle
      >
        Decline
      </button>
      <input
        type="text"
        name="resolution_note"
        placeholder="Note (optional)"
        class="input input-bordered input-xs hidden w-40"
        data-decline-note
      />
      <button
        type="submit"
        name="decision"
        value="decline"
        class="btn btn-ghost btn-xs hidden"
        data-decline-submit
      >
        Confirm decline
      </button>
    </span>
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
  The info-outlined "✎ Suggest: on/off" status pill — the band's toggle and,
  with `:explain`, the read-only variant shown above a card being edited in
  suggest mode.
  """
  attr :on?, :boolean, required: true
  attr :explain, :boolean, default: false
  attr :rest, :global

  def mode_pill(assigns) do
    ~H"""
    <span
      class={[
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-bold",
        if(@on?, do: "border-info bg-info/15 text-info", else: "border-info/40 text-info")
      ]}
      {@rest}
    >
      ✎ Suggest: {if @on?, do: "on", else: "off"}
      <span :if={@explain and @on?} class="font-normal">— your edits become proposals</span>
    </span>
    """
  end

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
          escape(JSON.encode!(to_string(key))),
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
    [~s(<span class="text-success">), escape(JSON.encode!(value)), "</span>"]
  end

  defp json_frag(value, _indent) when is_number(value) do
    [~s(<span class="text-warning">), JSON.encode!(value), "</span>"]
  end

  defp json_frag(value, _indent), do: escape(JSON.encode!(value))

  defp escape(binary) do
    {:safe, iodata} = Phoenix.HTML.html_escape(binary)
    iodata
  end
end
