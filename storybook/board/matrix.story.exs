# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Board.Matrix do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.BoardComponents.matrix/1

  def layout, do: :one_column

  # The board lays its columns across the page's full width.
  def container, do: {:div, class: "w-full"}

  defp columns(counts) do
    for {{key, label, dot}, count} <-
          Enum.zip(
            [
              {:submitted, "Submitted", "bg-warning"},
              {:triage, "Triage", "bg-info"},
              {:draft, "Draft", "bg-warning"},
              {:review, "Review", "bg-info"},
              {:approved, "Approved", "bg-[color:var(--violet)]"},
              {:publishing, "Publishing", "bg-info"}
            ],
            counts
          ) do
      %{key: key, label: label, dot: dot, count: count, empty?: count == 0}
    end
  end

  defp board_slots do
    [
      """
      <:row_head :let={row}>
        <div class="truncate font-mono text-[0.78rem] font-semibold">{row.label}</div>
      </:row_head>
      """,
      """
      <:cell :let={{row, column}}>
        <VarselWeb.BoardComponents.card :for={title <- Map.get(row.cards, column.key, [])}>
          <:title>{title}</:title>
          <:meta><VarselWeb.CoreComponents.severity_chip score={7.5} /></:meta>
        </VarselWeb.BoardComponents.card>
      </:cell>
      """
    ]
  end

  def variations do
    [
      %Variation{
        id: :pipeline,
        description:
          "A row per package, a column per stage. A stage holding nothing keeps its " <>
            "place as a narrow strip.",
        attributes: %{
          head: "Package",
          columns: columns([1, 0, 3, 1, 1, 0]),
          rows: [
            %{label: "No package", cards: %{submitted: ["Forged webhook events accepted"]}},
            %{
              label: "nerves_hub_web",
              cards: %{
                draft: [
                  "Session fixation in the CLI login flow",
                  "Mass assignment of organization"
                ],
                review: ["Missing authorization in device channels"]
              }
            },
            %{
              label: "cowboy",
              cards: %{
                draft: ["Unbounded buffering of request bodies"],
                approved: ["Header smuggling"]
              }
            }
          ]
        },
        slots: board_slots()
      },
      %Variation{
        id: :one_row,
        description: "Every case under one row: the matrix reads as a plain board.",
        attributes: %{
          head: "Package",
          columns: columns([0, 0, 2, 0, 0, 0]),
          rows: [
            %{
              label: "No package",
              cards: %{draft: ["Heap overflow in the packet parser", "Path traversal"]}
            }
          ]
        },
        slots: board_slots()
      }
    ]
  end
end
