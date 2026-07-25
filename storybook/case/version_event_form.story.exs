# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.VersionEventForm do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseFormComponents.version_event_form/1

  def layout, do: :one_column

  def description, do: "The commit or version where the vulnerability was introduced or fixed."

  def variations do
    [
      %Variation{
        id: :default,
        description: "Left unscoped, the boundary applies to the whole package.",
        attributes: %{form: form(), id: "event-form"},
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
        id: :scoped,
        description: "`channel_options` offers the channels the boundary can be pinned to.",
        attributes: %{
          form: form(),
          id: "event-scoped",
          channel_options: [{"pkg:otp/ssh", "chan-otp"}, {"pkg:hex/phoenix", "chan-hex"}]
        },
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
    Varsel.Cases.VersionEvent
    |> AshPhoenix.Form.for_create(:add, as: "child")
    |> Phoenix.Component.to_form()
  end
end
