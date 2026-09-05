# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CaseHeader do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.case_header/1

  def layout, do: :one_column

  @tabs [
    %{id: :workspace, label: "Workspace", navigate: "#workspace"},
    %{id: :cve, label: "CVE", navigate: "#cve"},
    %{id: :osv, label: "OSV", navigate: "#osv"},
    %{id: :publication, label: "Publication", navigate: "#publication"}
  ]

  def variations do
    [
      %Variation{
        id: :draft,
        description: "A draft with no CVE ID yet, on the workspace tab.",
        attributes: %{
          case_record: %{
            cve_id: nil,
            title: "Bandit reads a chunked body twice",
            inserted_at: ~U[2026-08-12 09:30:00Z],
            state: :draft
          },
          tabs: @tabs,
          active: :workspace
        },
        slots: [
          """
          <:actions>
            <button class="btn btn-sm btn-eef-quiet">Assign CVE ID</button>
            <button class="btn btn-sm btn-eef">Request review</button>
          </:actions>
          """
        ]
      },
      %Variation{
        id: :published,
        description: "A published case links its CVE ID to the public page.",
        attributes: %{
          case_record: %{
            cve_id: "CVE-2026-12345",
            title: "Bandit reads a chunked body twice",
            inserted_at: ~U[2026-08-12 09:30:00Z],
            state: :published
          },
          public_href: "#public",
          tabs: @tabs,
          active: :cve
        },
        slots: [
          """
          <:actions>
            <button class="btn btn-ghost btn-sm">Reopen</button>
          </:actions>
          """
        ]
      },
      %Variation{
        id: :closed,
        description: "A closed case shows the terminal pill and no actions.",
        attributes: %{
          case_record: %{
            cve_id: "CVE-2026-12346",
            title: "Withdrawn report",
            inserted_at: ~U[2026-08-12 09:30:00Z],
            state: :closed
          },
          tabs: @tabs,
          active: :publication
        }
      }
    ]
  end
end
