# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.TlpInput do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  alias Varsel.Cases.Case.Tlp

  def function, do: &VarselWeb.CaseFormComponents.tlp_input/1

  def layout, do: :one_column

  def description, do: "The TLP marking of a case: one card per label with what it permits, and the caveat."

  def variations do
    [
      %Variation{
        id: :red,
        description: "A new case, at TLP:RED.",
        attributes: %{field: field(%Tlp{label: :red})}
      },
      %Variation{
        id: :amber_strict,
        description: "A case shared inside the recipient's organization only, with a caveat.",
        attributes: %{
          field: field(%Tlp{label: :amber_strict, caveat: "Not the upstream vendor."})
        }
      }
    ]
  end

  defp field(tlp), do: Phoenix.Component.to_form(%{"tlp" => tlp}, as: "form")[:tlp]
end
