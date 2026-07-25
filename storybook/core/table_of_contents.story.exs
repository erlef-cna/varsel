# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.TableOfContents do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.table_of_contents/1

  def layout, do: :one_column

  # It fills the rail it stands in, rather than centring in the sandbox.
  def container, do: {:div, class: "w-64"}

  def variations do
    [
      %Variation{
        id: :flat,
        description: "The CVE record's sections, all one rank — the entries carry no `:level`.",
        attributes: %{
          entries: [
            %{id: "am-i-affected", label: "Am I affected?"},
            %{id: "description", label: "Description"},
            %{id: "affected", label: "Affected"},
            %{id: "references", label: "References"},
            %{id: "cvss", label: "CVSS breakdown"}
          ]
        }
      },
      %Variation{
        id: :nested,
        description: "A documentation page indents anything past the second rank.",
        attributes: %{
          entries: [
            %{id: "introduction", label: "Introduction", level: 2},
            %{id: "what-is-a-vulnerability", label: "What is a Vulnerability?", level: 2},
            %{id: "when-we-assign", label: "When We Assign a CVE", level: 2},
            %{id: "general-cases", label: "General Cases", level: 3},
            %{id: "ecosystem-specific", label: "Ecosystem-Specific: Internal Modules", level: 3},
            %{id: "checklist", label: "CNA Heuristic Checklist", level: 2}
          ]
        }
      },
      %Variation{
        id: :single_entry,
        description: "One heading still gets the rail — the page just says so briefly.",
        attributes: %{entries: [%{id: "description", label: "Description"}]}
      }
    ]
  end
end
