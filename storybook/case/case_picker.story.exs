# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CasePicker do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.case_picker/1

  @cases [
    %{
      id: "c1",
      title: "Bandit reads a chunked body twice",
      state: :draft,
      cve_id: "CVE-2026-12345"
    },
    %{id: "c2", title: "Plug leaks the session cookie on redirect", state: :triage, cve_id: nil},
    %{id: "c3", title: nil, state: :review, cve_id: "CVE-2026-12346"}
  ]

  def variations do
    [
      %Variation{
        id: :matches,
        description: "Every open case before the user types, one chosen.",
        attributes: %{query: "", cases: @cases, selected: "c2"}
      },
      %Variation{
        id: :more,
        description: "More cases match than are listed.",
        attributes: %{query: "bandit", cases: Enum.take(@cases, 1), more?: true}
      },
      %Variation{
        id: :no_match,
        description: "A query that matches nothing.",
        attributes: %{query: "nothing like this", cases: []}
      }
    ]
  end
end
