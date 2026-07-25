# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.CodeBlock do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.code_block/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  @cna_json """
  {
    "containers": {
      "cna": {
        "title": "Heap overflow in the packet parser",
        "affected": [
          {
            "vendor": "erlef",
            "product": "rabbit_common",
            "versions": [
              {"version": "3.12.0", "lessThan": "3.12.14", "status": "affected"}
            ]
          }
        ]
      }
    }
  }
  """

  def variations do
    [
      %Variation{
        id: :json,
        description: "The published CNA container, syntax-highlighted by Lumis.",
        attributes: %{source: @cna_json}
      },
      %Variation{
        id: :elixir,
        description: "`language` selects the lexer.",
        attributes: %{
          language: "elixir",
          source: """
          defmodule Varsel.CVE.Publisher do
            @spec publish(CveRecord.t()) :: {:ok, map()} | {:error, term()}
            def publish(%CveRecord{state: :draft} = record) do
              record |> render_cna() |> Mitre.submit()
            end
          end
          """
        }
      },
      %Variation{
        id: :short,
        description: "A one-line vector.",
        attributes: %{
          language: "text",
          source: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        }
      },
      %Variation{
        id: :capped_height,
        description: "`class` is for placement extras — here a scroll cap.",
        attributes: %{source: @cna_json, class: "max-h-40 overflow-y-auto"}
      }
    ]
  end
end
