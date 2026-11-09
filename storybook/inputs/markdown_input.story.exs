# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Inputs.MarkdownInput do
  @moduledoc false
  use PhoenixStorybook.Story, :live_component

  def component, do: VarselWeb.MarkdownInput

  def layout, do: :one_column

  defp field(value) do
    Phoenix.Component.to_form(%{"description_md" => value}, as: :case)[:description_md]
  end

  def variations do
    [
      %Variation{
        id: :write,
        description: """
        Opens in Write. Switch to Preview to render through the same pipeline
        the published record uses — each instance keeps its own tab state.
        """,
        attributes: %{
          field:
            field("""
            A heap overflow in the packet parser allows a **remote** attacker to
            crash the node.

            ## Workaround

            Upgrade to `3.12.14`.
            """),
          label: "Description"
        }
      },
      %Variation{
        id: :empty,
        description: "Previewing an empty field says so rather than showing a blank box.",
        attributes: %{
          field: field(nil),
          label: "Description",
          placeholder: "Describe the vulnerability…"
        }
      },
      %Variation{
        id: :comment,
        description: """
        A comment composer: typing `@` offers the people in `mentionable`. Preview renders mentions and emoji
        shortcodes as the posted comment will.
        """,
        attributes: %{
          field: field("Thanks :tada: [@Sam Chen](mention:0190c0de-0000-7000-8000-00000000000b)"),
          label: "Comment",
          flavor: :comment,
          viewer_id: "0190c0de-0000-7000-8000-00000000000a",
          mentionable: [
            %{id: "0190c0de-0000-7000-8000-00000000000b", name: "Sam Chen"},
            %{id: "0190c0de-0000-7000-8000-00000000000c", name: "Ana Lima"}
          ]
        }
      },
      %Variation{
        id: :tall,
        description: "`rows` sizes the textarea.",
        attributes: %{
          field: field("Reported privately by the RabbitMQ security team."),
          label: "Credits",
          rows: 10
        }
      }
    ]
  end
end
