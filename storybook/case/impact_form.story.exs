# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ImpactForm do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseFormComponents.impact_form/1

  def layout, do: :one_column

  def description, do: "A CAPEC classification, picked from the catalog."

  # A catalog small enough to read in a story; the real one carries the
  # whole CAPEC list.
  @catalog_options %{capec: [{63, "Cross-Site Scripting"}, {66, "SQL Injection"}]}

  def variations do
    [
      %Variation{
        id: :default,
        description: "The picker offers the CAPEC catalog as a datalist.",
        attributes: %{form: form(), id: "impact-form", catalog_options: @catalog_options},
        slots: [
          """
          <:actions>
            <div class="flex gap-2 mt-4">
              <button type="button" class="btn btn-primary btn-sm">Save</button>
              <button type="button" class="btn btn-ghost btn-sm">Cancel</button>
            </div>
          </:actions>
          """
        ]
      }
    ]
  end

  # The form only ever reads the changeset, so an unsubmitted create form off
  # the resource renders one without a case or a database.
  defp form do
    Varsel.Cases.CaseImpact
    |> AshPhoenix.Form.for_create(:add, as: "child")
    |> Phoenix.Component.to_form()
  end
end
