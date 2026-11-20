# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.CvssBreakdown do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.cvss_breakdown/1

  def layout, do: :one_column

  def description, do: "The base metrics of a CVSS vector in words; each value explains itself on hover."

  def variations do
    [
      %Variation{
        id: :v4,
        description: "CVSS v4.0: exploitability, then the vulnerable and the subsequent systems.",
        attributes: %{vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}
      },
      %Variation{
        id: :v4_with_threat,
        description: "Metrics beyond the base ones are left out.",
        attributes: %{
          vector: "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P"
        }
      },
      %Variation{
        id: :v3_1,
        description: "CVSS v3.1: exploitability, then the impact with its scope.",
        attributes: %{vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}
      },
      %Variation{
        id: :v3_0,
        description: "CVSS v3.0 reads the same as v3.1.",
        attributes: %{vector: "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N"}
      },
      %Variation{
        id: :unreadable,
        description: "A vector that does not read renders nothing.",
        attributes: %{vector: "CVSS:4.0/bogus"}
      }
    ]
  end
end
