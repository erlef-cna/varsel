# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.Markdown do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.markdown/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :default,
        description: "Case prose, rendered through the same pipeline the record publishes.",
        attributes: %{
          content: """
          A heap overflow in the packet parser allows a remote attacker to crash
          the node by sending a malformed AMQP frame.

          ## Impact

          Any node accepting connections from untrusted peers is affected.
          The overflow is **not** believed to be exploitable beyond a crash.

          ## Workaround

          Restrict access to the AMQP port, or upgrade to `3.12.14`.
          """
        }
      },
      %Variation{
        id: :lists_and_code,
        attributes: %{
          content: """
          Steps to reproduce:

          1. Start a node with default settings
          2. Connect and send a frame with a declared size of `0xFFFFFFFF`
          3. Observe the crash in the log

          ```elixir
          :gen_tcp.send(socket, <<0xFF, 0xFF, 0xFF, 0xFF>>)
          ```
          """
        }
      },
      %Variation{
        id: :html_is_escaped,
        description: "Raw HTML in the source is escaped, not rendered — comrak's `unsafe` is off.",
        attributes: %{
          content: """
          A report body may contain markup: <script>alert('xss')</script>

          It is shown as text.
          """
        }
      },
      %Variation{
        id: :compact,
        description: "`class` tunes the prose scale — `prose-xs` is used inside feed entries.",
        attributes: %{
          class: "prose-xs",
          content: "Confirmed against `3.12.13` — the crash reproduces reliably."
        }
      }
    ]
  end
end
