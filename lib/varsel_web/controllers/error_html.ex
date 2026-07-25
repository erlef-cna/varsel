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
  column. Renders only `<main>` content — nav and footer come from the root
  layout on both the exception path and the controller `render_404` path, so
  embedding them here would double the chrome (see config.exs render_errors).
  """
  attr :context, :string,
    default: "Error",
    doc: ~s(eyebrow context word, e.g. "Error" or "CVE record")

  attr :status, :integer, required: true
  attr :subtitle, :string, default: nil
  slot :title, required: true
  slot :inner_block, required: true

  def error_page(assigns) do
    ~H"""
    <.console_header eyebrow={"#{@context} · HTTP #{@status}"} subtitle={@subtitle}>
      <:title>{render_slot(@title)}</:title>
    </.console_header>

    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-10">
      <div class="max-w-2xl">
        {render_slot(@inner_block)}
      </div>
    </div>
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
