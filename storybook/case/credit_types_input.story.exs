# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CreditTypesInput do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseFormComponents.credit_types_input/1

  def layout, do: :one_column

  def description, do: "Every role a credited person had, one checkbox per credit type."

  def variations do
    [
      %Variation{
        id: :none_checked,
        description: "No role chosen yet.",
        attributes: %{field: field([])}
      },
      %Variation{
        id: :several_checked,
        description: "A person who found, reported and fixed the vulnerability.",
        attributes: %{field: field([:finder, :reporter, :remediation_developer])}
      },
      %Variation{
        id: :with_error,
        description: "Submitted with every box unchecked.",
        attributes: %{field: field([], credit_types: {"must have %{count} item(s)", count: 1})}
      }
    ]
  end

  defp field(types, errors \\ []) do
    Phoenix.Component.to_form(%{"credit_types" => types}, as: "child", errors: errors)[
      :credit_types
    ]
  end
end
