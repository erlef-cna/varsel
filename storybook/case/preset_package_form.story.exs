# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.PresetPackageForm do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseFormComponents.preset_package_form/1

  def layout, do: :one_column

  def description,
    do:
      "A package added from a preset: vendor, product, repository and channels come with it, so only boundary facts and affected files are asked for."

  def variations do
    [
      %Variation{
        id: :otp,
        description: "Erlang/OTP — applications are named per OTP app.",
        attributes: %{form: form(:add_otp), preset: :otp, id: "preset-otp"},
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
        id: :elixir,
        description: "Elixir — the same shape, with Elixir-flavoured placeholders.",
        attributes: %{form: form(:add_elixir), preset: :elixir, id: "preset-elixir"},
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
        id: :gleam,
        description: "Gleam has no applications, so that field drops out entirely.",
        attributes: %{form: form(:add_gleam), preset: :gleam, id: "preset-gleam"},
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
  defp form(action) do
    Varsel.Cases.AffectedPackage
    |> AshPhoenix.Form.for_create(action, as: "child")
    |> Phoenix.Component.to_form()
  end
end
