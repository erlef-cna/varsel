# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ReportPayload do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.report_payload/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def description, do: "A free-form vulnerability report payload, in the shapes it arrives in."

  @body """
  The packet parser fails to bound the declared frame length before
  allocating, so a crafted frame header sends the node into a heap
  overflow.

  * affected from `3.12.0` up to `3.12.14`
  * reachable from any unauthenticated peer
  """

  def variations do
    [
      %Variation{
        id: :markdown_body,
        description: "A `report` string is the body, and reads as Markdown.",
        attributes: %{
          payload: %{"report" => @body},
          report_id: "story-md"
        }
      },
      %Variation{
        id: :body_with_leftovers,
        description: "Anything else the payload carries sits behind the disclosure, closed.",
        attributes: %{
          payload: %{"report" => @body, "affected" => "rabbit_common", "cvss" => 9.8},
          report_id: "story-both"
        }
      },
      %Variation{
        id: :body_with_leftovers_open,
        description: "The same, with the caller holding the disclosure open.",
        attributes: %{
          payload: %{"report" => @body, "affected" => "rabbit_common", "cvss" => 9.8},
          report_id: "story-both-open",
          expanded?: true
        }
      },
      %Variation{
        id: :json_only,
        description: "With no body to lift out, the payload is the report — so it renders open.",
        attributes: %{
          payload: %{"package" => "acme_lib", "details" => "leaks secrets", "version" => "< 1.2"},
          report_id: "story-json"
        }
      },
      %Variation{
        id: :clamped,
        description: "`body_class` is the clamp — tighter in the case rail than in the queue.",
        attributes: %{
          payload: %{"report" => @body},
          report_id: "story-clamped",
          body_class: "max-h-24 overflow-y-auto"
        }
      },
      %Variation{
        id: :empty,
        description: "An empty payload renders nothing at all.",
        attributes: %{payload: %{}, report_id: "story-empty"}
      }
    ]
  end
end
