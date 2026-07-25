# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ChannelForm do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseFormComponents.channel_form/1

  def layout, do: :one_column

  def description, do: "The purl that names a package on one registry, and the part of the repository it ships."

  def variations do
    [
      %Variation{
        id: :default,
        description: "The form as it opens for a new channel.",
        attributes: %{form: form(), id: "channel-form"},
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
    Varsel.Cases.PackageChannel
    |> AshPhoenix.Form.for_create(:add, as: "child")
    |> Phoenix.Component.to_form()
  end
end
