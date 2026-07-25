# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.SectionNav do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.section_nav/1

  def layout, do: :one_column

  # The rail is a narrow left-hand column in the workspace.
  def container, do: {:div, class: "w-64"}

  def variations do
    [
      %Variation{
        id: :default,
        description: """
        Readiness markers: ✓ ready, ● needs work, ◆ n open suggestions. The
        `suggestions` count wins over the status marker when non-zero.
        """,
        attributes: %{
          id: "rail-default",
          sections: [
            %{id: "summary", label: "Summary", status: :ok},
            %{id: "description", label: "Description", status: :ok},
            %{id: "packages", label: "Affected packages", status: :attention},
            %{id: "references", label: "References", status: :ok, suggestions: 2},
            %{id: "credits", label: "Credits", status: :attention},
            %{id: "suggestions", label: "All suggestions", status: :ok, suggestions: 3}
          ]
        }
      },
      %Variation{
        id: :all_ready,
        description: "A case ready to submit — every section checks out.",
        attributes: %{
          id: "rail-ready",
          sections: [
            %{id: "summary", label: "Summary", status: :ok},
            %{id: "description", label: "Description", status: :ok},
            %{id: "packages", label: "Affected packages", status: :ok},
            %{id: "references", label: "References", status: :ok}
          ]
        }
      },
      %Variation{
        id: :long_labels,
        description: "Labels truncate rather than wrapping the rail.",
        attributes: %{
          id: "rail-long",
          sections: [
            %{id: "summary", label: "Summary", status: :ok},
            %{
              id: "packages",
              label: "Affected packages and version ranges",
              status: :attention,
              suggestions: 12
            }
          ]
        }
      }
    ]
  end
end
