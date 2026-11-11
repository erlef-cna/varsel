# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CaseActions do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.case_actions/1

  def variations do
    [
      %Variation{
        id: :reporter,
        description: "The reporter of a submitted case can only withdraw.",
        attributes: %{actions: [:withdraw]}
      },
      %Variation{
        id: :triage,
        description: "A POC triaging a report. Split, merge and reject sit under the menu.",
        attributes: %{actions: [:accept, :triage, :split, :merge, :reject]}
      },
      %Variation{
        id: :draft,
        description: "A POC on a draft without a CVE ID.",
        attributes: %{actions: [:assign_cve_id, :request_review, :close]}
      },
      %Variation{
        id: :review,
        description: "A POC reviewing a case.",
        attributes: %{actions: [:request_changes, :approve, :reopen, :close]}
      },
      %Variation{
        id: :approved,
        description: "An approved case links to the Publication tab.",
        attributes: %{actions: [:publish, :reopen], publish_href: "#publication"}
      },
      %Variation{
        id: :published,
        description: "A published case can only be reopened for an amendment.",
        attributes: %{actions: [:reopen]}
      },
      %Variation{
        id: :none,
        description: "An actor with no action renders an empty bar.",
        attributes: %{actions: []}
      }
    ]
  end
end
