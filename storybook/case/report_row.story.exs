# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ReportRow do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.report_row/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full rounded-box border border-base-300 bg-base-200"}

  def description, do: "One vulnerability report as a row of a list card."

  @body """
  The packet parser fails to bound the declared frame length before
  allocating, so a crafted frame header sends the node into a heap
  overflow.
  """

  @reporter %{name: "Ada Lovelace", display_name: "Ada Lovelace", avatar_url: nil}

  defp report(attrs) do
    Map.merge(
      %{
        id: "story-report",
        summary: "rabbit_common overflows on a crafted frame header",
        state: :submitted,
        inserted_at: ~U[2026-08-12 09:30:00Z],
        triage_notes: nil,
        report_json: %{"report" => @body},
        reporter: @reporter
      },
      attrs
    )
  end

  def variations do
    [
      %Variation{
        id: :submitted,
        description: "An open report carries full weight.",
        attributes: %{report: report(%{id: "story-submitted"})}
      },
      %Variation{
        id: :accepted_with_notes,
        description: "A resolved report quiets down; triage notes follow the body.",
        attributes: %{
          report:
            report(%{
              id: "story-accepted",
              state: :accepted,
              triage_notes: "Confirmed against 3.12.13."
            })
        }
      },
      %Variation{
        id: :rejected,
        description: "A rejected report.",
        attributes: %{
          report: report(%{id: "story-rejected", state: :rejected, triage_notes: "Out of scope."})
        }
      },
      %Variation{
        id: :reporter_hidden,
        description: "`reporter?` false names nobody.",
        attributes: %{report: report(%{id: "story-anonymous"}), reporter?: false}
      },
      %Variation{
        id: :no_payload,
        description: "`payload?` false shows only the head: a reporter's own list.",
        attributes: %{report: report(%{id: "story-head"}), payload?: false}
      },
      %Variation{
        id: :with_actions,
        description: "The caller adds controls beside the state and content at the foot.",
        attributes: %{report: report(%{id: "story-actions"})},
        slots: [
          """
          <:actions>
            <button class="btn btn-outline btn-error btn-xs">Withdraw</button>
          </:actions>
          <div class="mt-3 pt-3 border-t border-base-300">
            <button class="btn btn-eef btn-sm">Accept into case</button>
          </div>
          """
        ]
      }
    ]
  end
end
