# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.SuggestionDiff do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.suggestion_diff/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :merged,
        description: """
        Two similar prose values merge into one neutral body: removed words
        struck in red, added words green.
        """,
        attributes: %{
          old: "A heap overflow in the packet parser allows an attacker to crash the node.",
          new: "A heap overflow in the AMQP frame parser allows a remote attacker to crash the node."
        }
      },
      %Variation{
        id: :stacked_rewrite,
        description: "Values too dissimilar to merge stack as old-then-new blocks.",
        attributes: %{
          old: "Crash on malformed input.",
          new: """
          Sending an AMQP frame whose declared payload size exceeds the
          remaining buffer causes an out-of-bounds read.
          """
        }
      },
      %Variation{
        id: :addition,
        description: "A pure addition — no old side to show.",
        attributes: %{old: nil, new: "Reported by the RabbitMQ security team."}
      },
      %Variation{
        id: :removal,
        description: "A pure removal.",
        attributes: %{old: "This issue is disputed by the maintainer.", new: nil}
      },
      %Variation{
        id: :cvss_vector,
        description: """
        Slash-delimited single tokens (CVSS vectors) additionally emphasise the
        changed `/`-segments, so the one edited metric stands out of an
        otherwise identical pair.
        """,
        attributes: %{
          old: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
          new: "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        }
      },
      %Variation{
        id: :folded_paragraphs,
        description: """
        Runs of untouched paragraphs fold behind a toggle — click the "⋯ N
        unchanged paragraphs" row to expand them.
        """,
        attributes: %{
          old: """
          The parser reads a length prefix from the frame header.

          This value is used to size the receive buffer.

          No bounds check is performed before the copy.

          The impact is limited to a node crash.
          """,
          new: """
          The parser reads a length prefix from the frame header.

          This value is used to size the receive buffer.

          No bounds check is performed before the copy.

          The impact is a node crash, and possibly memory disclosure.
          """
        }
      }
    ]
  end
end
