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
        cases: [%{state: :submitted, accepted_at: nil}],
        inserted_at: ~U[2026-08-12 09:30:00Z],
        report_json: %{"report" => @body},
        reporter_id: "story-reporter",
        reporter_username: nil,
        reporter: @reporter
      },
      attrs
    )
  end

  def variations do
    [
      %Variation{
        id: :submitted,
        description: "A report whose case awaits a decision carries full weight.",
        attributes: %{report: report(%{id: "story-submitted"})}
      },
      %Variation{
        id: :under_triage,
        description: "A POC marked its case under triage.",
        attributes: %{
          report: report(%{id: "story-triage", cases: [%{state: :triage, accepted_at: nil}]})
        }
      },
      %Variation{
        id: :accepted,
        description: "A report quiets down once the CNA accepted one of its cases.",
        attributes: %{
          report:
            report(%{
              id: "story-accepted",
              cases: [%{state: :draft, accepted_at: ~U[2026-08-13 10:00:00Z]}]
            })
        }
      },
      %Variation{
        id: :closed,
        description: "Every case it opened closed or merged without acceptance.",
        attributes: %{
          report: report(%{id: "story-closed", cases: [%{state: :closed, accepted_at: nil}]})
        }
      },
      %Variation{
        id: :by_handle,
        description: "hex.pm sent it, and the reporter has not signed in yet: the handle names them.",
        attributes: %{
          report:
            report(%{
              id: "story-handle",
              reporter_id: nil,
              reporter: nil,
              reporter_username: Ash.CiString.new("ada_l")
            })
        }
      },
      %Variation{
        id: :reporter_hidden,
        description: "`reporter?` false names nobody.",
        attributes: %{report: report(%{id: "story-anonymous"}), reporter?: false}
      },
      %Variation{
        id: :no_payload,
        description: "`payload?` false shows only the head.",
        attributes: %{report: report(%{id: "story-head"}), payload?: false}
      },
      %Variation{
        id: :with_actions,
        description: "The caller adds controls beside the status and content at the foot.",
        attributes: %{report: report(%{id: "story-actions"})},
        slots: [
          """
          <:actions>
            <button class="btn btn-outline btn-error btn-xs">Withdraw</button>
          </:actions>
          <div class="mt-3 pt-3 border-t border-base-300">
            <a class="link text-primary text-sm">Open the case →</a>
          </div>
          """
        ]
      }
    ]
  end
end
