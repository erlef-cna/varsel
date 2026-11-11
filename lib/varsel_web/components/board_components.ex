# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.BoardComponents do
  @moduledoc """
  The pipeline board: a matrix of cards, a column per stage of the work and a
  row per thing the work is grouped by.

  The page fills the slots with its own markup and wraps a card in whatever
  makes it clickable.
  """
  use Phoenix.Component

  import VarselWeb.CoreComponents, only: [icon: 1]

  @doc """
  Renders the board: a row per entry of `rows` under a head row naming the
  `columns`, so what belongs to one row lines up across every column.

  A column with nothing in any row keeps its place as a narrow strip, and the
  columns holding cards share the width that leaves. The board scrolls
  sideways when they do not fit.

  `row_head` receives the row, `cell` receives `{row, column}`.

  Give it `targets_event` and `move_event` and a card can be dragged to
  another column of its row. A card is whatever the page marks `data-card`
  with its id, made `draggable`. When a drag starts the board pushes
  `targets_event` with that `id` and expects `%{targets: [column keys]}`
  back: those cells offer the move, and the row's other cells show that it
  is refused. A drop pushes `move_event` with the `id` and the column as `to`.
  """
  attr :id, :string, default: nil, doc: "the board's DOM id, required for dragging"
  attr :head, :string, required: true, doc: "names what the rows are, above the row heads"

  attr :columns, :list,
    required: true,
    doc:
      "maps of `key`, `label`, `dot` (a background colour class), `count`, `empty?` and optionally `id`, the head cell's DOM id"

  attr :rows, :list, required: true
  attr :targets_event, :string, default: nil, doc: "asks which columns a card may move to"
  attr :move_event, :string, default: nil, doc: "moves a card to a column"
  attr :class, :any, default: nil

  slot :row_head, required: true, doc: "what a row stands for"
  slot :cell, required: true, doc: "the cards of one row in one column"

  def matrix(assigns) do
    ~H"""
    <div
      id={@id}
      phx-hook={@move_event && "BoardMove"}
      data-targets-event={@targets_event}
      data-move-event={@move_event}
      class={["overflow-x-auto rounded-box border border-base-300 bg-base-200" | List.wrap(@class)]}
    >
      <div class="min-w-[60rem]">
        <div class="flex border-b border-base-300 text-[0.7rem] font-bold uppercase tracking-wider text-base-content/70">
          <div class="w-44 flex-none px-3.5 py-2.5">{@head}</div>
          <div
            :for={column <- @columns}
            id={column[:id]}
            title={column.label}
            class={[
              "flex items-center gap-2 border-l border-base-300 px-2.5 py-2.5",
              column_width(column),
              column.empty? && "justify-center"
            ]}
          >
            <span class={["size-1.5 rounded-full shrink-0", column.dot]}></span>
            <span class={[column.empty? && "sr-only"]}>{column.label}</span>
            <span class={[!column.empty? && "ml-auto", "text-base-content/70 tabular-nums font-bold"]}>
              {column.count}
            </span>
          </div>
        </div>

        <div :for={row <- @rows} data-row class="flex border-b border-base-300 last:border-b-0">
          <div class="w-44 flex-none px-3.5 py-2.5">{render_slot(@row_head, row)}</div>
          <div
            :for={column <- @columns}
            data-column={column.key}
            class={[
              "group/cell flex flex-col gap-1.5 border-l border-base-300 p-2",
              column_width(column)
            ]}
          >
            {render_slot(@cell, {row, column})}
            <.drop_placeholders :if={@move_event} column={column} />
          </div>
        </div>
      </div>
    </div>
    """
  end

  attr :column, :map, required: true

  defp drop_placeholders(assigns) do
    ~H"""
    <div class={[
      "hidden min-h-[var(--board-card-height,4.9rem)] items-center justify-center gap-1.5 rounded-lg border border-dashed py-2 text-[0.72rem] font-semibold",
      "border-[color:var(--eef-blue)] text-[color:var(--eef-blue)]",
      "group-data-[drop=allowed]/cell:flex group-data-[drop-over]/cell:bg-[color:var(--eef-blue)]/15",
      !@column.empty? && "px-2.5"
    ]}>
      <.icon name="hero-arrow-down-on-square-mini" class="size-4 shrink-0" />
      <span class={[@column.empty? && "sr-only"]}>Move to {@column.label}</span>
    </div>
    <div class={[
      "hidden min-h-[var(--board-card-height,4.9rem)] cursor-not-allowed items-center justify-center gap-1.5 rounded-lg border border-dashed py-2 text-[0.72rem] font-semibold",
      "border-base-content/30 text-base-content/70",
      "group-data-[drop=denied]/cell:flex",
      !@column.empty? && "px-2.5"
    ]}>
      <.icon name="hero-no-symbol-mini" class="size-4 shrink-0" />
      <span class={[@column.empty? && "sr-only"]}>Can't move here</span>
    </div>
    """
  end

  defp column_width(%{empty?: true}), do: "w-24 flex-none"
  defp column_width(_column), do: "flex-1 basis-0 min-w-[11rem]"

  @doc """
  Renders one card: a title of up to two lines over a line of marks.
  """
  attr :class, :any, default: nil

  slot :title, required: true
  slot :meta, doc: "the line under the title: severity, a reference, an age, who holds it"

  def card(assigns) do
    ~H"""
    <div class={[
      "lane-card rounded-lg border border-base-300 px-2.5 py-2 transition-colors duration-150 hover:border-[color:var(--eef-blue)] cursor-pointer"
      | List.wrap(@class)
    ]}>
      <div class="line-clamp-2 text-[0.78rem] font-semibold leading-snug">{render_slot(@title)}</div>
      <div :if={@meta != []} class="mt-1.5 flex flex-wrap items-center gap-x-1.5 gap-y-1">
        {render_slot(@meta)}
      </div>
    </div>
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
