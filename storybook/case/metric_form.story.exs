# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.MetricForm do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseFormComponents.metric_form/1

  def layout, do: :one_column

  def description, do: "A CVSS v4.0 score and the plain-text scenario it applies to."

  @actions """
  <:actions>
    <div class="flex gap-2 mt-4">
      <button type="button" class="btn btn-primary btn-sm">Save</button>
      <button type="button" class="btn btn-ghost btn-sm">Cancel</button>
    </div>
  </:actions>
  """

  def variations do
    [
      %Variation{
        id: :general,
        description: "A case's first score is the GENERAL scenario.",
        attributes: %{form: form(%{}), id: "metric-form-general"},
        slots: [@actions]
      },
      %Variation{
        id: :scenario,
        description: "A further scenario names the conditions its score applies to.",
        attributes: %{
          form:
            form(%{
              "scenario" => "The VM is built without stack protection.",
              "cvss_v4" => "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            }),
          id: "metric-form-scenario"
        },
        slots: [@actions]
      },
      %Variation{
        id: :propose,
        description: "In suggest mode the form asks for the reasoning.",
        attributes: %{form: form(%{}), id: "metric-form-propose", propose?: true},
        slots: [@actions]
      }
    ]
  end

  # The form only ever reads the changeset, so an unsubmitted create form off
  # the resource renders one without a case or a database.
  defp form(params) do
    Varsel.Cases.CaseMetric
    |> AshPhoenix.Form.for_create(:add, as: "child", params: params)
    |> Phoenix.Component.to_form()
  end
end
