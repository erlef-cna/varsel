# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseComponents do
  @moduledoc """
  Components of the case pages: the header every tab shares, the lifecycle
  stepper, the section rail with readiness markers, the unified activity
  feed, and rendered case markdown.
  """

  use Phoenix.Component

  import Phoenix.HTML, only: [raw: 1]

  import VarselWeb.CoreComponents,
    only: [code_block: 1, copy_button: 1, mono_chip: 1, page_header: 1, scope_tab: 1]

  import VarselWeb.UserComponents, only: [avatar_disc: 1, user_name: 1]

  alias Phoenix.LiveView.JS
  alias Varsel.Cases.Markdown
  alias Varsel.Cases.WordDiff

  @lifecycle [draft: "Draft", review: "Review", approved: "Approved", published: "Published"]

  @doc """
  Renders the band every case tab shares: the CVE ID, the title, the
  lifecycle stepper, the actions, and the tabs that lead to the other pages
  of the case.
  """
  attr :case_record, :map,
    required: true,
    doc: "needs `:cve_id`, `:title`, `:inserted_at` and `:state`"

  attr :public_href, :string,
    default: nil,
    doc: "the public CVE page, once the record is published"

  attr :tabs, :list,
    required: true,
    doc: "maps of `:id`, `:label` and `:navigate`, in display order"

  attr :active, :atom, required: true, doc: "the `:id` of the tab this page is"

  slot :actions, doc: "the lifecycle actions and anything else the tab offers"

  def case_header(assigns) do
    ~H"""
    <.page_header>
      <:eyebrow>
        Case
        <span :if={@case_record.cve_id} class="font-mono">
          ·
          <.link
            :if={@public_href}
            href={@public_href}
            title="View the published CVE page"
            class="link link-hover"
          >{@case_record.cve_id}</.link>
          <span :if={is_nil(@public_href)}>{@case_record.cve_id}</span>
        </span>
        <.copy_button
          :if={@case_record.cve_id}
          value={@case_record.cve_id}
          label={"Copy #{@case_record.cve_id}"}
          class="align-text-bottom"
        />
        <span :if={is_nil(@case_record.cve_id)} class="opacity-60">· no CVE ID assigned</span>
        <span class="text-base-content/50">
          · draft opened {Calendar.strftime(@case_record.inserted_at, "%b %-d, %Y")}
        </span>
      </:eyebrow>
      <:title>{@case_record.title || "Untitled case"}</:title>
      <:meta>
        <.lifecycle_stepper state={@case_record.state} />
        <div class="flex items-center gap-4 text-sm mt-3">
          <.link :for={tab <- @tabs} navigate={tab.navigate}>
            <.scope_tab active?={tab.id == @active} label={tab.label} />
          </.link>
        </div>
      </:meta>
      <:actions :if={@actions != []}>{render_slot(@actions)}</:actions>
    </.page_header>
    """
  end

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
      <.link
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
      </.link>
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
          <.user_name user={entry.who} class="font-semibold text-base-content/90" />
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
        <.user_name user={@proposal.author} class="font-bold" />
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
              who: comment.author,
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

  defp suggestion_target_field(%{operation: :set, target: :case, field_name: field}), do: "case.#{field}"

  defp suggestion_target_field(%{operation: :set, target: target, field_name: field}) do
    "#{target}.#{field}"
  end

  defp suggestion_target_field(%{operation: :insert, target: target}), do: "+ #{target}"
  defp suggestion_target_field(%{operation: :delete, target: target}), do: "− #{target}"

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

  @doc "Renders case markdown with prose styling."
  attr :content, :string, required: true
  attr :class, :any, default: nil

  def markdown(assigns) do
    ~H"""
    <div class={["prose prose-sm max-w-none", @class]}>{raw(Markdown.to_display_html(@content))}</div>
    """
  end

  @doc """
  Renders a free-form vulnerability report payload, in the two shapes it
  arrives in.

  Reports carry an arbitrary map; only `"report"` is ever assumed. A string
  under that key is the body the reporter wrote and reads as Markdown, with
  whatever else the payload holds tucked into a disclosure beside it. A
  payload with no such body *is* the report, so it renders open — there would
  otherwise be nothing to show.

  The caller owns the disclosure: pass `toggle` to drive it from a LiveView
  (`expanded?` then says whether it is open), or leave it `nil` for a plain
  `<details>` that needs no state. `body_class` is the clamp, which differs
  between the queue and the narrower case rail.
  """
  attr :payload, :any, required: true
  attr :report_id, :string, required: true, doc: ~s(not `id` — storybook eats an `id` attr)
  attr :expanded?, :boolean, default: false
  attr :toggle, :string, default: nil, doc: "the event a click on the disclosure pushes"
  attr :body_class, :any, default: nil
  attr :json_class, :any, default: nil

  def report_payload(assigns) do
    body = report_body(assigns.payload)

    assigns =
      assign(assigns,
        body: body,
        json: if(body, do: payload_rest(assigns.payload), else: presence(assigns.payload)),
        # With no body lifted out of it, the payload is all the report says.
        always_open?: is_nil(body)
      )

    ~H"""
    <.markdown
      :if={@body}
      content={@body}
      class={["prose-xs rounded-lg border border-base-300 bg-base-100 px-3 py-2", @body_class]}
    />

    <div :if={@json} class={[@body && "mt-2"]}>
      <button
        :if={not @always_open?}
        type="button"
        class="text-xs font-semibold text-base-content/60 hover:text-base-content cursor-pointer"
        phx-click={@toggle}
        phx-value-report_id={@report_id}
      >
        {if @expanded?, do: "Report payload ▴", else: "Report payload ▾"}
      </button>
      <.code_block
        :if={@always_open? or @expanded?}
        source={pretty_json(@json)}
        class={["overflow-y-auto", not @always_open? && "mt-1.5", @json_class || "max-h-72"]}
      />
    </div>
    """
  end

  defp report_body(%{"report" => body}) when is_binary(body), do: body
  defp report_body(_payload), do: nil

  defp payload_rest(payload), do: payload |> Map.delete("report") |> presence()

  # An empty payload has nothing to disclose; `{}` is not worth a codebox.
  defp presence(payload) when payload == %{} or is_nil(payload), do: nil
  defp presence(payload), do: payload

  # Jason, not the stdlib JSON module: only Jason has a pretty printer.
  defp pretty_json(value), do: Jason.encode!(value, pretty: true)

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
  Renders the affected source files of a package, each path followed by the
  modules and routines it contributes.
  """
  attr :files, :list, required: true, doc: "the package's `%ProgramFile{}` list"

  def program_files(assigns) do
    ~H"""
    <div class="text-[0.68rem] font-bold uppercase tracking-wider text-base-content/50 mb-1.5">
      Program files
    </div>
    <%!-- Inline text flow (not a flex row): path and chips wrap as one line
          of text, so every row breaks the same way regardless of path
          length. --%>
    <div :if={@files != []} class="space-y-1">
      <div :for={file <- @files} class="min-w-0 text-xs leading-6">
        <span class="font-mono text-base-content/70 break-all">{file.path}</span>
        <.mono_chip :for={name <- file.modules ++ file.routines} size={:small} class="ml-1">
          {name}
        </.mono_chip>
      </div>
    </div>
    <p :if={@files == []} class="text-sm text-base-content/60">
      No program files recorded.
    </p>
    """
  end

  @doc """
  What a proposal would do: the catalog entry a weakness or impact names, the
  row a removal targets, the raw JSON for anything else.

  `removing` is that targeted row, which only the caller can resolve.
  """
  attr :proposal, :any, required: true
  attr :removing, :any, default: nil, doc: "the row a :delete proposal targets"
  attr :class, :any, default: nil

  def proposal_payload(%{proposal: %{operation: :insert, target: target}} = assigns)
      when target in [:weakness, :impact] do
    assigns = assign(assigns, :entry, catalog_entry(assigns.proposal))

    ~H"""
    <p :if={@entry} class="mt-1 text-sm">
      <.catalog_link entry={@entry} />
    </p>
    """
  end

  def proposal_payload(%{proposal: %{operation: :delete}} = assigns) do
    assigns = assign(assigns, :entry, removed_entry(assigns.removing))

    ~H"""
    <p :if={@entry} class="mt-1 text-sm line-through decoration-error/40">
      <.catalog_link :if={@entry.url} entry={@entry} />
      <span :if={is_nil(@entry.url)} class="font-mono">{@entry.name}</span>
    </p>
    """
  end

  def proposal_payload(%{proposal: %{operation: operation, proposed_value: value}} = assigns)
      when operation != :set and not is_nil(value) do
    ~H"""
    <.code_block
      source={Jason.encode!(@proposal.proposed_value["value"], pretty: true)}
      class={@class}
    />
    """
  end

  def proposal_payload(assigns), do: ~H""

  attr :entry, :map, required: true

  defp catalog_link(assigns) do
    ~H"""
    <.link href={@entry.url} target="_blank" rel="noopener noreferrer" class="link font-mono">
      {@entry.id}
    </.link>
    {@entry.name}
    """
  end

  defp catalog_entry(%{target: :weakness, proposed_value: %{"value" => %{"cwe_id" => cwe_id}}}) do
    cwe_entry(cwe_id, with_name(Varsel.CWE.get_weakness(cwe_id)))
  end

  defp catalog_entry(%{target: :impact, proposed_value: %{"value" => %{"capec_id" => capec_id}}}) do
    capec_entry(capec_id, with_name(Varsel.CAPEC.get_attack_pattern(capec_id)))
  end

  defp catalog_entry(_proposal), do: nil

  defp with_name({:ok, %{name: name}}), do: name
  defp with_name({:error, _not_found}), do: nil

  defp removed_entry(%Varsel.Cases.CaseWeakness{} = weakness) do
    cwe_entry(weakness.cwe_id, catalog_name(weakness, :weakness))
  end

  defp removed_entry(%Varsel.Cases.CaseImpact{} = impact) do
    capec_entry(impact.capec_id, catalog_name(impact, :attack_pattern))
  end

  defp removed_entry(%Varsel.Cases.CaseReference{} = reference), do: %{id: nil, name: reference.url, url: nil}

  defp removed_entry(%Varsel.Cases.CaseCredit{} = credit), do: %{id: nil, name: credit.name, url: nil}

  defp removed_entry(%Varsel.Cases.AffectedPackage{} = package) do
    %{id: nil, name: "#{package.vendor} / #{package.product}", url: nil}
  end

  defp removed_entry(_row), do: nil

  defp catalog_name(row, key) do
    case Map.get(row, key) do
      %{name: name} -> name
      _not_loaded -> nil
    end
  end

  defp cwe_entry(id, name), do: entry("CWE", id, name, "https://cwe.mitre.org/data/definitions")

  defp capec_entry(id, name), do: entry("CAPEC", id, name, "https://capec.mitre.org/data/definitions")

  defp entry(prefix, id, name, base_url) do
    %{id: "#{prefix}-#{id}", name: name || "(not in catalog)", url: "#{base_url}/#{id}.html"}
  end

  @doc """
  Renders a settled suggestion: what it asked for, how it was resolved, and
  the note whoever resolved it left. Unlike `suggestion_card/1` this one is
  read-only — a resolved proposal has nothing left to accept or decline.
  """
  attr :proposal, :any, required: true

  def resolved_proposal_card(assigns) do
    ~H"""
    <div class="rounded-lg border border-base-300 bg-base-300/30 p-3 text-sm">
      <div class="flex items-center justify-between gap-2">
        <span class="font-semibold truncate">{proposal_summary(@proposal)}</span>
        <span class={["badge badge-sm shrink-0", proposal_badge_class(@proposal.state)]}>
          {@proposal.state}
        </span>
      </div>

      <.proposal_payload proposal={@proposal} class="mt-1 max-h-96" />

      <div :if={@proposal.reasoning} class="mt-1 text-base-content/80">
        <.markdown content={@proposal.reasoning} class="prose-xs" />
      </div>

      <p class="mt-1 text-xs text-base-content/60">
        by <.user_name user={@proposal.author} /> · {relative_time(@proposal.inserted_at)}
        <span :if={@proposal.resolved_by}>
          · resolved by <.user_name user={@proposal.resolved_by} />
        </span>
      </p>

      <p :if={@proposal.resolution_note} class="mt-1 text-xs text-base-content/60 italic">
        {@proposal.resolution_note}
      </p>
    </div>
    """
  end

  defp proposal_summary(proposal) do
    target = proposal.target |> to_string() |> String.replace("_", " ")

    case proposal.operation do
      :set -> "set #{target}.#{proposal.field_name}"
      :insert -> "add #{target}"
      :delete -> "remove #{target}"
    end
  end

  defp proposal_badge_class(:open), do: "badge-warning"
  defp proposal_badge_class(:accepted), do: "badge-success"
  defp proposal_badge_class(:declined), do: "badge-error"
  defp proposal_badge_class(_other), do: "badge-ghost"

  @doc """
  Renders the row that closes an edit: commit, abandon, and — while
  suggesting — the reasoning carried onto the suggestion.

  What the buttons say and how the commit is styled follow `mode`, since a
  suggestion is a different act from an edit. `cancel` names the event
  abandoning it, which is the caller's to handle.
  """
  attr :mode, :atom, required: true, values: [:view, :edit, :propose]
  attr :cancel, :string, required: true, doc: "the event abandoning the edit"

  def edit_actions(assigns) do
    ~H"""
    <div class="flex items-end gap-2 mt-4">
      <button
        type="submit"
        class={[
          "btn btn-sm",
          if(@mode == :propose, do: "btn-info text-info-content", else: "btn-primary")
        ]}
      >
        {if @mode == :propose, do: "Suggest changes", else: "Save changes"}
      </button>
      <button type="button" class="btn btn-eef-quiet btn-sm" phx-click={@cancel}>
        Cancel
      </button>
      <input
        :if={@mode == :propose}
        type="text"
        name="reasoning"
        placeholder="Reasoning (attached to the suggestion, optional)"
        class="input input-bordered input-sm flex-1"
      />
    </div>
    """
  end

  @doc """
  Renders the rider above an open editor saying the edits will become
  suggestions. Renders nothing outside propose mode.
  """
  attr :mode, :atom, required: true, values: [:view, :edit, :propose]

  def edit_mode_notice(assigns) do
    ~H"""
    <div class="flex justify-end mb-2">
      <.mode_pill :if={@mode == :propose} on?={true} explain={true} />
    </div>
    """
  end

  @doc """
  Renders what a row's proposals have made of it: proposed for a row that only
  a suggestion puts there, removal proposed for one a suggestion would take
  away. A row no suggestion touches renders nothing.
  """
  attr :row_id, :any, required: true, doc: "the row's id, looked up in the marks"
  attr :marks, :map, required: true, doc: "%{phantom: MapSet, deleted: MapSet}"

  def proposal_marks(assigns) do
    ~H"""
    <span :if={@row_id in @marks.phantom} class="badge badge-info badge-xs">proposed</span>
    <span :if={@row_id in @marks.deleted} class="badge badge-error badge-xs">
      removal proposed
    </span>
    """
  end

  @doc """
  Renders what can still be done to a row: edit it, or remove it. A row a
  suggestion already covers offers neither — its marks say so instead — and
  neither does a case being read rather than worked on.

  `noun` names the thing in the confirm ("Remove this channel?"), and `edit`
  labels the way in, which the dense editor spells as a caret. Both buttons
  push their event with the row's `type` and `id`, for the caller to handle.
  """
  attr :row_id, :any, required: true
  attr :type, :string, required: true, doc: ~s(the child type, e.g. "channel")
  attr :noun, :string, required: true, doc: ~s(what the confirm calls it, e.g. "channel")
  attr :mode, :atom, required: true, values: [:view, :edit, :propose]
  attr :marks, :map, required: true
  attr :edit_label, :string, default: "Edit"

  def row_actions(assigns) do
    ~H"""
    <span
      :if={@mode != :view and @row_id not in @marks.phantom and @row_id not in @marks.deleted}
      class="contents"
    >
      <button
        class="link link-hover text-primary text-xs"
        phx-click="edit_child"
        phx-value-type={@type}
        phx-value-id={@row_id}
      >
        {@edit_label}
      </button>
      <button
        class="link link-hover text-xs text-base-content/50 hover:text-error ml-2"
        phx-click="remove_child"
        phx-value-type={@type}
        phx-value-id={@row_id}
        data-confirm={
          if @mode == :propose,
            do: "Propose removing this #{@noun}?",
            else: "Remove this #{@noun}?"
        }
      >
        {if @mode == :propose, do: "Propose removal", else: "Remove"}
      </button>
    </span>
    """
  end

  @doc """
  Renders the small heading above a part of a card, with whatever adds to it
  along the same line.

  The `actions` slot is the caller's — some parts add through a plain button,
  the affected list through a menu of package kinds.
  """
  attr :title, :string, required: true
  attr :level, :atom, default: :h4, values: [:h2, :h4], doc: "the heading rank it takes"

  slot :actions

  def card_section_header(assigns) do
    ~H"""
    <div class="flex items-center justify-between mb-1">
      <h2
        :if={@level == :h2}
        class="text-[0.68rem] font-bold uppercase tracking-wider text-base-content/60"
      >
        {@title}
      </h2>
      <h4
        :if={@level == :h4}
        class="text-[0.68rem] font-bold uppercase tracking-wider text-base-content/50"
      >
        {@title}
      </h4>
      {render_slot(@actions)}
    </div>
    """
  end

  @doc """
  Renders the record's readiness as a checklist: one row per check that
  passed, one per finding that has not.

  Each row is a map of `:ok`, `:text` and an optional `:section` — the part of
  the workspace that fixes it. The `jump` slot renders per row that names one,
  since where the link goes and what dismissing the preview does are both the
  caller's.
  """
  attr :rows, :list, required: true

  slot :jump, doc: "the way to the section a finding points at" do
    attr :section, :string
  end

  def validation_checklist(assigns) do
    ~H"""
    <ul class="text-[0.79rem]">
      <li :for={row <- @rows} class="flex items-center gap-2 py-1 text-base-content/70">
        <span :if={row.ok} class="shrink-0 font-bold text-success">✓</span>
        <span :if={!row.ok} class="shrink-0 font-bold text-warning">✗</span>
        <span class="min-w-0">{row.text}</span>
        <span :if={row.section} class="ml-auto shrink-0">{render_slot(@jump, row)}</span>
      </li>
    </ul>
    """
  end

  @doc """
  Renders a case's written content at rest: what the vulnerability is,
  followed by the sections that say what to do about it.

  Each of `configurations`, `workarounds` and `solutions` appears only when
  the case has something to say there, under its own heading.

  `affected_summary` is the "This issue affects …" sentence the published
  record appends to the description. It is shown here, muted and labelled, so
  an author can see what the reader will get without being able to edit it —
  and so nobody writes it a second time by hand.

  `internal_notes` is the one part of this panel that never reaches the
  record, so it renders last, collapsed, and marked as internal — a plain
  `<details>`, since nothing here needs LiveView state.
  """
  attr :description, :string, default: nil
  attr :affected_summary, :string, default: nil
  attr :configurations, :string, default: nil
  attr :workarounds, :string, default: nil
  attr :solutions, :string, default: nil
  attr :internal_notes, :string, default: nil

  def case_content(assigns) do
    ~H"""
    <div class="space-y-4">
      <.markdown :if={@description} content={@description} />
      <p :if={is_nil(@description)} class="text-base-content/60">No description yet.</p>

      <div :if={@affected_summary} class="rounded border border-base-300/70 bg-base-200/40 p-3">
        <p class="mb-1 text-[0.62rem] font-bold uppercase tracking-wide text-base-content/50">
          appended on publish
        </p>
        <p class="text-sm text-base-content/70">{@affected_summary}</p>
      </div>

      <div :for={
        {label, content} <- [
          {"Configurations", @configurations},
          {"Workarounds", @workarounds},
          {"Solutions", @solutions}
        ]
      }>
        <div :if={content}>
          <h3 class="text-sm font-semibold text-base-content/70 mb-1">{label}</h3>
          <.markdown content={content} />
        </div>
      </div>

      <details :if={@internal_notes} class="rounded border border-dashed border-base-300 p-2">
        <summary class="cursor-pointer text-[0.62rem] font-bold uppercase tracking-wide text-base-content/50">
          internal notes — never published
        </summary>
        <.markdown content={@internal_notes} class="mt-2" />
      </details>
    </div>
    """
  end
end
