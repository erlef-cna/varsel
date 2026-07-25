# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.SuggestionCard do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.suggestion_card/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  defp ago(seconds), do: DateTime.add(DateTime.utc_now(), -seconds, :second)

  # The card reads plain fields off the proposal, so a map stands in for the
  # Ash struct — no repo round-trip needed to render one.
  defp proposal(overrides \\ %{}) do
    Map.merge(
      %{
        id: "prop-1",
        operation: :set,
        target: :case,
        field_name: :description_md,
        state: :open,
        reasoning: nil,
        inserted_at: ago(1800),
        author: %{name: "Sam Chen"}
      },
      overrides
    )
  end

  def variations do
    [
      %Variation{
        id: :open,
        description: "An open suggestion as a reader sees it — no resolve controls.",
        attributes: %{
          id: "suggestion-open",
          proposal: proposal(),
          old: "Crash on malformed input.",
          new: "A remote attacker can crash the node with a malformed AMQP frame."
        }
      },
      %Variation{
        id: :resolvable,
        description: "`can_resolve` adds Accept and the two-step Decline control.",
        attributes: %{
          id: "suggestion-resolvable",
          can_resolve: true,
          proposal:
            proposal(%{
              reasoning: "The original wording does not say **who** can trigger it."
            }),
          old: "Crash on malformed input.",
          new: "A remote attacker can crash the node with a malformed AMQP frame."
        }
      },
      %Variation{
        id: :own_suggestion,
        description: "Your own open suggestion offers Withdraw instead.",
        attributes: %{
          id: "suggestion-own",
          own: true,
          proposal: proposal(%{author: %{name: "Alex Rivera", github_handle: "maennchen"}}),
          old: "3.12.13",
          new: "3.12.14"
        }
      },
      %Variation{
        id: :with_thread,
        description: "A reply count toggles the proposal's comment thread.",
        attributes: %{
          id: "suggestion-thread",
          can_resolve: true,
          proposal: proposal(%{field_name: :cvss_v4}),
          old: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
          new: "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
          comments: [
            %{
              id: "c1",
              body: "Attack complexity is High — you need to win a race first.",
              inserted_at: ago(900),
              author: %{name: "Sam Chen"}
            },
            %{
              id: "c2",
              body: "Agreed, and privileges required should be Low.",
              inserted_at: ago(600),
              author: %{name: "Alex Rivera"}
            }
          ]
        }
      },
      %Variation{
        id: :insert_operation,
        description: """
        Non-`:set` operations carry no old→new diff; the caller renders the raw
        payload in the default slot instead.
        """,
        attributes: %{
          id: "suggestion-insert",
          can_resolve: true,
          proposal: proposal(%{operation: :insert, target: :reference, field_name: nil})
        },
        slots: [
          """
          <div class="mt-2 rounded-md border border-base-300 p-2 font-mono text-xs">
            https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-xxxx
          </div>
          """
        ]
      },
      %Variation{
        id: :resolved,
        description: "A resolved suggestion keeps the record but drops the action row.",
        attributes: %{
          id: "suggestion-resolved",
          can_resolve: true,
          proposal: proposal(%{state: :accepted, inserted_at: ago(4 * 86_400)}),
          old: "Crash on malformed input.",
          new: "A remote attacker can crash the node with a malformed AMQP frame."
        }
      }
    ]
  end
end
