# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Inputs.CvssInput do
  @moduledoc false
  use PhoenixStorybook.Story, :live_component

  def component, do: VarselWeb.CvssInput

  def layout, do: :one_column

  # The component reads its value from a form field and writes back to it, so
  # each variation gets its own single-field form.
  defp field(value) do
    Phoenix.Component.to_form(%{"cvss_v4" => value}, as: :case)[:cvss_v4]
  end

  def variations do
    [
      %Variation{
        id: :empty,
        description: """
        Live calculator. Toggling any metric from empty starts at the
        all-benign baseline (score 0.0) and applies the click.
        """,
        attributes: %{field: field(nil)}
      },
      %Variation{
        id: :critical,
        description: "A pasted vector drives the toggles and the score chip.",
        attributes: %{
          field: field("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        }
      },
      %Variation{
        id: :medium,
        attributes: %{
          field: field("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")
        }
      },
      %Variation{
        id: :invalid,
        description: "An unparseable vector shows the \"invalid vector\" badge and no score.",
        attributes: %{field: field("CVSS:4.0/AV:Q/nonsense")}
      },
      %Variation{
        id: :custom_label,
        attributes: %{
          field: field("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
          label: "Severity (CVSS v4.0)"
        }
      }
    ]
  end
end
