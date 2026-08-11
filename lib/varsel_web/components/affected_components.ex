# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AffectedComponents do
  @moduledoc """
  The affected product: what ships where, and which versions of it carry the
  flaw.

  A product is one row in the case and several in the published record — one
  per distribution channel. These components draw that nesting: the product
  frames, each channel hangs off a rule beneath it, and a channel's derived
  ranges read exactly as they will read once published, because they render
  through the same `VarselWeb.CveView` components the public record uses.

  Everything here is display only. Each component takes plain data and a slot
  for whatever verbs the caller allows, so the same block serves the read-only,
  editing and suggesting faces of the workspace without knowing which it is in.
  """

  use Phoenix.Component

  import VarselWeb.CaseComponents, only: [relative_timestamp: 1]
  import VarselWeb.CveView, only: [affected_range_list: 1, package_display_name: 1]

  alias VarselWeb.CveHTML
  alias VarselWeb.TimelineComponents

  @doc """
  One distribution channel: how it is named, what it distributes, and the
  version ranges derived for it.

  The left rule is the nesting — a channel belongs to the product above it.
  Ranges print through the published record's own range list, so an author
  reads them in the vocabulary the record will use; the timeline underneath
  turns the same ranges into a picture of where the flaw lived.

  A channel versioned in commit SHAs has no picture to draw (a commit graph is
  not a line), so it carries ranges alone.
  """
  attr :id, :string, default: nil
  attr :purl, :string, default: nil, doc: "the channel's composed Package URL"
  attr :fallback, :string, default: nil, doc: "what to call a channel with no purl, e.g. a domain"
  attr :subpath, :string, default: nil, doc: "the repository directory it distributes"

  attr :versions, :list,
    default: [],
    doc: ~s(the channel's derived CVE `versions[]`, as `derivation_cache` holds them)

  attr :timeline, :map, default: nil, doc: "%{label:, nodes:, spans:} from Derivation.Display"
  attr :timeline_id, :string, default: nil
  attr :muted, :boolean, default: false, doc: "dim the block, e.g. a row a proposal would remove"

  slot :badges, doc: "chips beside the name — overrides, proposal marks"
  slot :actions, doc: "the verbs offered for this channel"
  slot :problem, doc: "what is wrong with this channel specifically"

  def channel_block(assigns) do
    assigns = assign(assigns, :ranges, ranges(assigns.versions))

    ~H"""
    <div id={@id} class={["border-l-2 border-base-300 pl-3", @muted && "opacity-50"]}>
      <div class="flex flex-wrap items-center gap-2">
        <.package_display_name
          :if={@purl || @fallback}
          purl={@purl}
          fallback={@fallback}
          class="font-mono text-xs"
        />
        <span :if={@subpath} class="font-mono text-[0.68rem] text-base-content/40">{@subpath}</span>
        {render_slot(@badges)}
        <span
          :if={@actions != []}
          class="ml-auto flex shrink-0 items-center gap-3 text-xs font-semibold"
        >
          {render_slot(@actions)}
        </span>
      </div>

      <.affected_range_list :if={@ranges != []} ranges={@ranges} class="affected-range mt-1 text-xs" />

      <p :if={@ranges == [] and @problem == []} class="mt-1 text-xs text-base-content/50">
        no derived range
      </p>

      {render_slot(@problem)}

      <TimelineComponents.version_timeline
        :if={@timeline}
        id={@timeline_id}
        label={@timeline.label}
        nodes={@timeline.nodes}
        spans={@timeline.spans}
      />
    </div>
    """
  end

  defp ranges([]), do: []
  defp ranges(versions), do: CveHTML.affected_ranges(%{"versions" => versions})

  @doc """
  One vulnerability boundary fact: where the flaw entered the product or left
  it.

  The kind leads, tinted the way the timeline tints its nodes, so a column of
  facts reads as a sequence rather than a table. A fact scoped to one channel
  says so — that scoping is the whole reason two facts can disagree — and the
  note, which is where an author explains a boundary a reviewer would
  otherwise have to reconstruct, wraps underneath rather than being clipped
  into a cell.
  """
  attr :event, :atom, required: true, values: [:introduced, :fixed]
  attr :reference, :string, required: true, doc: "the commit SHA or version, already shortened"
  attr :title, :string, default: nil, doc: "the full value, for the hover"
  attr :scope, :string, default: nil, doc: "the channel this fact is limited to"
  attr :note, :string, default: nil
  attr :muted, :boolean, default: false

  slot :badges
  slot :actions

  def boundary_fact(assigns) do
    ~H"""
    <div class={["flex flex-wrap items-baseline gap-2 py-1", @muted && "opacity-50"]}>
      <span class={["badge badge-sm shrink-0", boundary_tone(@event)]}>{@event}</span>
      <span class="font-mono text-xs text-base-content/80" title={@title}>{@reference}</span>
      <span
        :if={@scope}
        class="badge badge-ghost badge-sm font-mono"
        title="Applies to this channel only"
      >
        {@scope}
      </span>
      {render_slot(@badges)}
      <span
        :if={@actions != []}
        class="ml-auto flex shrink-0 items-center gap-3 text-xs font-semibold"
      >
        {render_slot(@actions)}
      </span>
      <p :if={@note} class="w-full text-xs text-base-content/60">{@note}</p>
    </div>
    """
  end

  defp boundary_tone(:fixed), do: "text-success bg-success/15"
  defp boundary_tone(:introduced), do: "text-warning bg-warning/15"

  @doc """
  One affected source file, with the modules and routines it contributes.

  The path leads because that is what a reader matches against their own tree;
  what it contributes is subordinate to it, and absent for a file listed on its
  own.
  """
  attr :path, :string, required: true
  attr :modules, :list, default: []
  attr :routines, :list, default: []

  def program_file(assigns) do
    ~H"""
    <div class="py-1">
      <p class="break-all font-mono text-xs text-base-content/80">{@path}</p>
      <p :if={@modules != []} class="mt-0.5 break-all font-mono text-[0.68rem] text-base-content/50">
        {Enum.join(@modules, " · ")}
      </p>
      <p :if={@routines != []} class="mt-0.5 break-all font-mono text-[0.68rem] text-base-content/50">
        {Enum.join(@routines, " · ")}
      </p>
    </div>
    """
  end

  @doc """
  What the derived ranges below are currently worth, and the way to renew them.

  Deriving is explicit, so the ranges on screen can be anything from
  authoritative to actively misleading, and the difference is invisible in the
  ranges themselves. The state leads in its own colour: an outdated derivation
  is a warning because the versions being read are wrong, an unrun one is
  neutral because nothing is being claimed yet, and a current one recedes.

  Refreshing recomputes the whole case, not this product alone, so the button
  says so rather than implying a scope it does not have.
  """
  attr :state, :atom, required: true, values: [:never, :outdated, :ageing, :current]
  attr :at, :any, default: nil, doc: "when the derivation last ran"
  attr :can_refresh, :boolean, default: false
  attr :refreshing, :boolean, default: false

  def derivation_status(assigns) do
    ~H"""
    <span class="flex items-center gap-2 text-xs">
      <span class={["flex items-center gap-1.5", state_tone(@state)]}>
        <span class={["size-1.5 shrink-0 rounded-full", state_dot(@state)]} aria-hidden="true"></span>
        {state_label(@state)}
      </span>

      <span :if={@at && @state != :never} class="text-base-content/40">
        <.relative_timestamp at={@at} />
      </span>

      <button
        :if={@can_refresh}
        class={["link link-hover", refresh_tone(@state)]}
        phx-click="refresh_derivation"
        disabled={@refreshing}
        title="Recomputes every product in this case"
      >
        {if @refreshing, do: "Deriving…", else: "Derive the case"}
      </button>
    </span>
    """
  end

  @doc """
  A quiet mark for one product's derivation, for when the case-wide status is
  reported elsewhere and the only open question is *which* product is behind.

  Renders nothing for a product that is as derived as it can be — a case is
  usually all-current, and a row of "fine" marks would say nothing while
  costing a reader the effort of checking each one.
  """
  attr :state, :atom, default: nil, values: [nil, :never, :outdated, :ageing, :current]

  def derivation_marker(%{state: state} = assigns) when state in [nil, :current, :ageing] do
    ~H""
  end

  def derivation_marker(assigns) do
    ~H"""
    <span class={["text-[0.68rem] font-semibold normal-case tracking-normal", state_tone(@state)]}>
      {state_label(@state)}
    </span>
    """
  end

  defp state_label(:never), do: "not derived"
  defp state_label(:outdated), do: "out of date"
  defp state_label(:ageing), do: "derived"
  defp state_label(:current), do: "derived"

  # Outdated is the only state that makes the ranges *wrong*, so it is the only
  # one that warns; the rest report without colouring the whole card.
  defp state_tone(:outdated), do: "text-warning font-semibold"
  defp state_tone(:never), do: "text-base-content/60"
  defp state_tone(_current), do: "text-base-content/50"

  defp state_dot(:outdated), do: "bg-warning"
  defp state_dot(:never), do: "bg-base-content/30"
  defp state_dot(:ageing), do: "bg-success/40"
  defp state_dot(:current), do: "bg-success"

  defp refresh_tone(state) when state in [:outdated, :never], do: "text-warning font-semibold"
  defp refresh_tone(_current), do: "text-primary"

  @doc """
  The header line under a product's title: where its source lives and the
  standing exceptions that change how its versions are read.

  Both are facts about the product a reviewer needs before reading a single
  range — an unreleased-fix allowance in particular explains a range that would
  otherwise look wrong.
  """
  attr :repo_url, :string, default: nil
  attr :notes, :list, default: [], doc: "standing exceptions, e.g. \"allows unreleased fixes\""

  def product_meta(assigns) do
    ~H"""
    <p
      :if={@repo_url || @notes != []}
      class="-mt-1.5 mb-2 font-mono text-xs text-base-content/60"
    >
      <span :if={@repo_url}>{@repo_url}</span>
      <span :for={note <- @notes} class="font-sans">· {note}</span>
    </p>
    """
  end
end
