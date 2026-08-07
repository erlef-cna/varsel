# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ErrorHTML do
  @moduledoc """
  This module is invoked by your endpoint in case of errors on HTML requests.

  See config/config.exs.
  """
  use VarselWeb, :html

  embed_templates "error_html/*"

  @doc """
  Shared shell for every error page: the console band plus a narrow body
  column. Renders only the body — each error template wraps it in
  `VarselWeb.Layouts.app/1` for the nav and footer, the same as any other
  page, so embedding them here would double the chrome.
  """
  attr :context, :string,
    default: "Error",
    doc: ~s(eyebrow context word, e.g. "Error" or "CVE record")

  attr :status, :integer, required: true
  attr :subtitle, :string, default: nil

  slot :title, required: true do
    attr :mono?, :boolean, doc: "the title is an identifier, e.g. a CVE ID"
  end

  slot :inner_block, required: true
  slot :actions, doc: "the row of ways on from here, along the body's foot"

  def error_page(assigns) do
    assigns = assign(assigns, :title_entry, hd(assigns.title))

    ~H"""
    <.page_header>
      <:eyebrow>{@context} · HTTP {@status}</:eyebrow>
      <:subtitle>{@subtitle}</:subtitle>
      <:title>
        <span class={[
          "block max-w-lg text-pretty [text-wrap:balance]",
          Map.get(@title_entry, :mono?) && "font-mono"
        ]}>
          {render_slot(@title_entry)}
        </span>
      </:title>
    </.page_header>

    <.page_container>
      <div class="max-w-2xl">
        {render_slot(@inner_block)}
        <div :if={@actions != []} class="mt-6 flex flex-wrap items-center gap-4">
          {render_slot(@actions)}
        </div>
      </div>
    </.page_container>
    """
  end

  def render(template, assigns) do
    assigns
    |> Map.put_new_lazy(:headline, fn ->
      Phoenix.Controller.status_message_from_template(template)
    end)
    |> Map.put_new_lazy(:status, fn ->
      case Integer.parse(template) do
        {num, _remainder} when num in 100..599 -> num
        _ -> 500
      end
    end)
    |> fallback()
  end
end
