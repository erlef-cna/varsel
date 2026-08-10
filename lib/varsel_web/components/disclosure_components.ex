# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.DisclosureComponents do
  @moduledoc """
  Progressive disclosure: sections that fold detail away without folding away
  what you can do about it.

  A collapsed `disclosure/1` still shows its title, how much it holds and its
  actions — only the rows go. That is the difference between "there are two
  boundary facts here, and you may add a third" and a toggle that hides both
  the content and the verbs, which is what makes a card's state feel like a
  mode rather than a view.

  `field_list/1` is the flat label/value pairing both the published record and
  the workspace use for the small print (default status, CPE, platforms).
  """

  use Phoenix.Component

  @doc """
  A foldable section: a header that stays put, and rows that come and go.

  The header carries the title, an optional count, and the `actions` slot —
  all of which remain visible while collapsed, so nothing actionable hides
  behind the fold.
  """
  attr :id, :string, required: true
  attr :title, :string, required: true
  attr :count, :integer, default: nil, doc: "how many rows are inside; hidden when nil"
  attr :open?, :boolean, default: false
  attr :class, :any, default: nil

  slot :actions, doc: "buttons that stay available whether or not the section is open"
  slot :empty, doc: "shown in place of the rows when count is 0"
  slot :inner_block, required: true

  def disclosure(assigns) do
    ~H"""
    <details id={@id} open={@open?} class={["group mt-3", @class]}>
      <summary class="flex cursor-pointer list-none items-center gap-2 border-t border-base-300 pt-2 text-[0.68rem] font-bold uppercase tracking-wider text-base-content/50 hover:text-base-content/70">
        <span class="inline-block transition-transform group-open:rotate-90" aria-hidden="true">
          ▸
        </span>
        {@title}
        <span :if={@count} class="font-sans font-semibold normal-case tracking-normal opacity-70">
          {@count}
        </span>
        <span
          :if={@actions != []}
          class="ml-auto flex items-center gap-3 text-xs font-semibold normal-case tracking-normal"
        >
          {render_slot(@actions)}
        </span>
      </summary>

      <div class="mt-2">
        <p :if={@count == 0 and @empty != []} class="text-xs text-base-content/50">
          {render_slot(@empty)}
        </p>
        {render_slot(@inner_block)}
      </div>
    </details>
    """
  end

  @doc """
  Label/value rows for an object's small print.

  `rows` are `{label, value}` pairs; a pair whose value is nil or empty is
  dropped, so callers can list every field they might show without guarding
  each one.
  """
  attr :rows, :list, required: true, doc: ~s({label, value} pairs)
  attr :mono, :boolean, default: true, doc: "render values in the mono face"
  attr :class, :any, default: nil

  def field_list(assigns) do
    assigns = assign(assigns, :rows, Enum.reject(assigns.rows, &blank_value?/1))

    ~H"""
    <div :if={@rows != []} class={["flex flex-col gap-0.5", @class]}>
      <div :for={{label, value} <- @rows} class="flex items-baseline gap-3 py-0.5">
        <span class="w-24 flex-shrink-0 text-[0.62rem] font-bold uppercase tracking-wide text-base-content/50">
          {label}
        </span>
        <span class={[
          "break-all text-xs text-base-content/70",
          @mono && "font-mono"
        ]}>
          {value}
        </span>
      </div>
    </div>
    """
  end

  defp blank_value?({_label, value}), do: value in [nil, "", []]
end
