# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.ListCard do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.list_card/1

  def layout, do: :one_column

  # A block-level card; the sandbox centers its children by default.
  def container, do: {:div, class: "w-full"}

  defp users_table do
    """
    <table class="table">
      <thead>
        <tr><th>Name</th><th>Email</th><th class="text-right">Role</th></tr>
      </thead>
      <tbody>
        <tr><td class="font-medium">Ada Lovelace</td><td class="text-base-content/70">ada@example.com</td><td class="text-right">POC</td></tr>
        <tr><td class="font-medium">Grace Hopper</td><td class="text-base-content/70">grace@example.com</td><td class="text-right">Supporter</td></tr>
      </tbody>
    </table>
    """
  end

  defp cve_table do
    """
    <table class="table">
      <thead>
        <tr><th>CVE ID</th><th>Title</th></tr>
      </thead>
      <tbody>
        <tr><td class="font-mono text-xs">CVE-2026-20011</td><td>Heap overflow in the packet parser</td></tr>
        <tr><td class="font-mono text-xs">CVE-2026-20004</td><td>Path traversal in archive extraction</td></tr>
      </tbody>
    </table>
    """
  end

  defp pager(summary) do
    """
    <:footer>
      <span>#{summary}</span>
      <span class="inline-flex items-center gap-2">
        <button type="button" class="px-1.5 rounded border border-base-300/50 text-base-content/40">«</button>
        Page
        <input type="text" value="1" class="w-9 text-center font-mono bg-base-100 border border-base-300 rounded px-1 py-0.5"/>
        of 2
        <button type="button" class="px-1.5 rounded border border-base-300">»</button>
      </span>
    </:footer>
    """
  end

  # A list that fits on one page keeps only its total — there is nowhere to
  # page to, so `pagination/1` drops the page size and the controls.
  defp count_only(summary), do: "<:footer><span>#{summary}</span></:footer>"

  def variations do
    [
      %Variation{
        id: :rows_and_count,
        description:
          "The settings lists: rows, and a footer saying how many there are. " <>
            "One page's worth, so the footer is only the count.",
        slots: [users_table(), count_only("4 users")]
      },
      %Variation{
        id: :rows_and_pager,
        description: "More than a page: the size and the controls join the count.",
        slots: [users_table(), pager("25 per page · 43 users")]
      },
      %Variation{
        id: :tabs,
        description: "The console lists filter themselves by scope; the tabs lead the bar.",
        slots: [
          """
          <:tabs>
            <button class="cursor-pointer pb-1 font-bold text-base-content shadow-[inset_0_-2px_0_var(--eef-blue)]">
              All <span class="font-semibold tabular-nums ml-1 text-primary">27</span>
            </button>
            <button class="cursor-pointer pb-1">
              Draft <span class="font-semibold tabular-nums ml-1 text-base-content/50">4</span>
            </button>
            <button class="cursor-pointer pb-1">
              Published <span class="font-semibold tabular-nums ml-1 text-base-content/50">23</span>
            </button>
          </:tabs>
          """,
          cve_table(),
          pager("25 per page · 27 records")
        ]
      },
      %Variation{
        id: :note,
        description: "A `note` trails the bar — the public list points at its machine-readable feeds.",
        slots: [
          """
          <:note>
            Machine-readable: <a href="#" class="link">JSON</a>
            · <a href="#" class="link">OSV</a>
            · <a href="#" class="link">Atom</a>
          </:note>
          """,
          cve_table(),
          count_only("2 CVEs")
        ]
      },
      %Variation{
        id: :tabs_and_note,
        description: "Both: the scopes lead, and a search summary trails.",
        slots: [
          """
          <:tabs>
            <button class="cursor-pointer pb-1 font-bold text-base-content shadow-[inset_0_-2px_0_var(--eef-blue)]">
              All <span class="font-semibold tabular-nums ml-1 text-primary">27</span>
            </button>
            <button class="cursor-pointer pb-1">
              Draft <span class="font-semibold tabular-nums ml-1 text-base-content/50">4</span>
            </button>
          </:tabs>
          """,
          ~s(<:note><span class="font-semibold text-info tabular-nums">2 match “overflow”</span></:note>),
          cve_table()
        ]
      },
      %Variation{
        id: :empty,
        description: "`empty?` swaps the rows for the `empty` slot's sentence.",
        attributes: %{empty?: true},
        slots: [
          "<:empty>No tokens yet — create one above.</:empty>",
          "<table class=\"table\"><tbody><tr><td>never rendered</td></tr></tbody></table>"
        ]
      },
      %Variation{
        id: :bare,
        description: "Without a bar or a footer the card is just the box its rows sit in.",
        slots: [users_table()]
      }
    ]
  end
end
