# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ResolvedProposalCard do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.resolved_proposal_card/1

  def layout, do: :one_column

  def description, do: "A settled suggestion — what it asked for, and how it was resolved."

  def variations do
    [
      %Variation{
        id: :accepted,
        description: "A field change that was taken, with the note its resolver left.",
        attributes: %{proposal: proposal(:accepted)}
      },
      %Variation{
        id: :declined,
        description: "Declined, so the state badge turns red.",
        attributes: %{
          proposal: %{
            proposal(:declined)
            | resolution_note: "Superseded by the vendor's own advisory."
          }
        }
      },
      %Variation{
        id: :insert,
        description: "An insert has no old→new diff, so the payload it proposed is rendered instead.",
        attributes: %{
          proposal: %{
            proposal(:accepted)
            | operation: :insert,
              target: :reference,
              field_name: nil,
              proposed_value: %{
                "value" => %{
                  "url" => "https://github.com/erlang/otp/security/advisories/GHSA-1234",
                  "tags" => ["patch"]
                }
              }
          }
        }
      },
      %Variation{
        id: :bare,
        description: "Neither reasoning nor a resolution note — the card shrinks to its byline.",
        attributes: %{
          proposal: %{proposal(:accepted) | reasoning: nil, resolution_note: nil}
        }
      }
    ]
  end

  defp ago(seconds), do: DateTime.shift(DateTime.utc_now(), second: -seconds)

  defp proposal(state) do
    %{
      target: :affected_package,
      field_name: "vendor",
      operation: :set,
      state: state,
      proposed_value: nil,
      reasoning: "The vendor is the foundation that publishes the package, not the project.",
      author: %{name: "Alice Hunt"},
      resolved_by: %{name: "Bob Reyes"},
      resolution_note: "Agreed — applied to the record.",
      inserted_at: ago(26 * 3600)
    }
  end
end
