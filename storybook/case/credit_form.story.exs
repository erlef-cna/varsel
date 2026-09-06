# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CreditForm do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseCredit.Handle

  def function, do: &VarselWeb.CaseFormComponents.credit_form/1

  def layout, do: :one_column

  def description, do: "Who contributed to the case, and how."

  def variations do
    [
      %Variation{
        id: :default,
        description: "The form as it opens for a new credit.",
        attributes: %{form: form(), id: "credit-form"},
        slots: [actions()]
      },
      %Variation{
        id: :with_handles,
        description: "Editing a credit that names the person's provider accounts.",
        attributes: %{form: edit_form(), id: "credit-edit-form"},
        slots: [actions()]
      }
    ]
  end

  defp actions do
    """
    <:actions>
      <div class="flex gap-2 mt-4">
        <button type="button" class="btn btn-primary btn-sm">Save</button>
        <button type="button" class="btn btn-ghost btn-sm">Cancel</button>
      </div>
    </:actions>
    """
  end

  # The form only ever reads the changeset, so an unsubmitted create form off
  # the resource renders one without a case or a database.
  defp form do
    CaseCredit
    |> AshPhoenix.Form.for_create(:add, as: "child")
    |> Phoenix.Component.to_form()
  end

  defp edit_form do
    %CaseCredit{
      id: Ash.UUID.generate(),
      name: "Jonatan Männchen",
      organization: "EEF",
      credit_type: :analyst,
      handles: [
        %Handle{
          strategy: :github,
          username: Ash.CiString.new("maennchen")
        },
        %Handle{strategy: :hex, username: Ash.CiString.new("maennchen")}
      ]
    }
    |> AshPhoenix.Form.for_update(:edit, as: "child")
    |> Phoenix.Component.to_form()
  end
end
