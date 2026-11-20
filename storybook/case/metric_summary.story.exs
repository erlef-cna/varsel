# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.MetricSummary do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.metric_summary/1

  def layout, do: :one_column

  def description, do: "One CVSS score of a case: chip, scenario and vector."

  def variations do
    [
      %Variation{
        id: :general,
        description: "The GENERAL scenario reads as General.",
        attributes: %{
          row_id: "metric-general",
          scenario: "GENERAL",
          vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
          score: 8.2
        }
      },
      %Variation{
        id: :scenario,
        description: "A further scenario names its condition above the vector.",
        attributes: %{
          row_id: "metric-scenario",
          scenario: "The VM is built without stack protection.",
          vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
          score: 9.2
        }
      },
      %Variation{
        id: :long_scenario,
        description: "A long scenario is clamped to two lines; the full text is on hover.",
        attributes: %{
          row_id: "metric-long",
          scenario:
            "The VM runs on a 32-bit platform, is built without stack protection, " <>
              "and accepts ASN.1 tag streams from unauthenticated peers with " <>
              "read-ahead disabled, which lets the attacker place return addresses.",
          vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
          score: 9.2
        }
      },
      %Variation{
        id: :unparsed,
        description: "A proposed vector that does not parse shows the scenario alone.",
        attributes: %{
          row_id: "metric-unparsed",
          scenario: "Local attacker",
          vector: nil,
          score: nil
        }
      }
    ]
  end
end
