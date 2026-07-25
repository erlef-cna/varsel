# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.AffectedPackageForm do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseFormComponents.affected_package_form/1

  def layout, do: :one_column

  def description, do: "Who ships the affected package, where it lives, and which of its files carry the vulnerability."

  def variations do
    [
      %Variation{
        id: :default,
        description: "The form as it opens for a new package.",
        attributes: %{form: form(), id: "package-form"},
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
      },
      %Variation{
        id: :propose,
        description: "`propose?` grows the reasoning line carried onto the suggestion.",
        attributes: %{form: form(), id: "package-propose", propose?: true},
        slots: [
          """
          <:actions>
            <div class="flex gap-2 mt-4">
              <button type="button" class="btn btn-primary btn-sm">Propose</button>
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
    Varsel.Cases.AffectedPackage
    |> AshPhoenix.Form.for_create(:add, as: "child")
    |> Phoenix.Component.to_form()
  end
end
