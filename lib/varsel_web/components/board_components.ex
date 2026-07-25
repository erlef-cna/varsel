# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.BoardComponents do
  @moduledoc """
  A kanban board: lanes side by side, each holding cards.

  The page fills the slots with its own markup and binds its own handlers to
  the controls it passes in.
  """
  use Phoenix.Component

  @doc """
  Renders the board: its lanes in a row, wrapping to one column on a narrow
  screen.
  """
  attr :class, :any, default: nil
  slot :inner_block, required: true

  def board(assigns) do
    ~H"""
    <div class={["grid grid-cols-1 md:grid-cols-4 gap-3 items-start" | List.wrap(@class)]}>
      {render_slot(@inner_block)}
    </div>
    """
  end

  @doc """
  Renders one lane: a titled column of cards.

  `dot` is the colour that stands for the lane's state, `count` what it holds.
  An empty lane keeps its place in the row, so the board's shape holds steady
  as work moves through it; on a narrow screen its body folds away.

  A lane showing only part of its cards puts the control for the rest in
  `footer`.
  """
  attr :id, :string, default: nil
  attr :label, :string, required: true
  attr :dot, :string, required: true, doc: ~s(a background colour class, e.g. "bg-warning")
  attr :count, :any, required: true, doc: "what the lane holds — shown at the head"
  attr :cards?, :boolean, default: true, doc: "the lane has cards to show"

  attr :quiet?, :boolean,
    default: false,
    doc: "the lane holds nothing at all, so it folds away on a narrow screen"

  slot :inner_block, required: true, doc: "the lane's cards"
  slot :footer, doc: "a control for cards the lane is not showing"

  def lane(assigns) do
    ~H"""
    <div id={@id} class="rounded-box border border-base-300 bg-base-200">
      <div class={[
        "flex items-center gap-2 px-3.5 py-2.5 text-[0.7rem] font-bold uppercase tracking-wider text-base-content/60 border-b border-base-300",
        @quiet? && "max-md:border-b-0"
      ]}>
        <span class={["size-1.5 rounded-full shrink-0", @dot]}></span>
        {@label}
        <span class="ml-auto text-base-content/50 tabular-nums font-bold">{@count}</span>
      </div>

      <div :if={@cards?} class="flex flex-col gap-2.5 p-2.5 min-h-12">
        {render_slot(@inner_block)}
      </div>
      <div
        :if={not @cards?}
        class={["text-center text-sm text-base-content/40 py-3", @quiet? && "max-md:hidden"]}
      >
        —
      </div>

      <div
        :for={footer <- @footer}
        class="w-full border-t border-base-300 text-center text-[0.74rem] font-semibold text-primary"
      >
        {render_slot(footer)}
      </div>
    </div>
    """
  end

  @doc """
  Renders one card: a title, a row of chips under it, and a footer line.

  The card is the frame; the page says what fills it, and wraps it in whatever
  makes it clickable.
  """
  attr :class, :any, default: nil

  slot :title, required: true
  slot :chips, doc: "severity, packages — whatever marks the card at a glance"
  slot :footer, doc: "the quiet line under the card: a reference, an age, who holds it"

  def card(assigns) do
    ~H"""
    <div class={[
      "lane-card block rounded-lg border border-base-300 p-2.5 hover:border-[color:var(--eef-blue)] cursor-pointer"
      | List.wrap(@class)
    ]}>
      <div class="text-[0.8rem] font-semibold leading-snug">{render_slot(@title)}</div>
      <div :if={@chips != []} class="flex flex-wrap gap-1.5 mt-2">{render_slot(@chips)}</div>
      <div :if={@footer != []} class="flex items-center justify-between gap-2 mt-2.5">
        {render_slot(@footer)}
      </div>
    </div>
    """
  end

  @doc """
  Renders a card chip: a short mono label naming something the card is about.
  """
  slot :inner_block, required: true

  def card_chip(assigns) do
    ~H"""
    <span class="font-mono text-[0.71rem] text-base-content/60 bg-base-200 border border-base-300 rounded px-1.5 py-0.5 whitespace-nowrap">
      {render_slot(@inner_block)}
    </span>
    """
  end

  @doc """
  Renders the dashed disc a card shows where nobody has picked it up.
  """
  attr :title, :string, default: "Needs an owner"

  def unclaimed_disc(assigns) do
    ~H"""
    <span
      class="inline-flex size-[21px] shrink-0 items-center justify-center rounded-full border-[1.5px] border-dashed border-base-content/40 text-base-content/40 text-xs"
      title={@title}
    >
      –
    </span>
    """
  end
end
