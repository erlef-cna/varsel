# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ValidationChecklist do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.validation_checklist/1

  def layout, do: :one_column

  def description, do: "Whether the record is ready to publish, check by check."

  def variations do
    [
      %Variation{
        id: :ready,
        description: "Every check passed — nothing stands in the way of publishing.",
        attributes: %{
          rows: [
            %{ok: true, text: "CVE record schema", section: nil},
            %{ok: true, text: "cvelint", section: nil},
            %{ok: true, text: "Hex packages exist", section: nil}
          ]
        }
      },
      %Variation{
        id: :blocked,
        description:
          "Findings sit alongside the checks that passed, each pointing at the " <>
            "part of the workspace that settles it.",
        attributes: %{
          rows: [
            %{ok: true, text: "CVE record schema", section: nil},
            %{ok: false, text: "no CVE ID assigned", section: nil},
            %{ok: false, text: "at least one affected package is required", section: "affected"},
            %{ok: false, text: "a description is required", section: "summary"}
          ]
        },
        slots: [
          ~s|<:jump><a href="#" class="link link-hover text-xs text-primary">Go to section</a></:jump>|
        ]
      },
      %Variation{
        id: :without_jumps,
        description: "With no jump slot, findings state themselves and nothing more.",
        attributes: %{
          rows: [
            %{ok: false, text: "at least one affected package is required", section: "affected"}
          ]
        }
      }
    ]
  end
end
