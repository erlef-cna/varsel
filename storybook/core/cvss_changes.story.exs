# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.CvssChanges do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.cvss_changes/1

  def layout, do: :one_column

  def description, do: "The base metrics two CVSS vectors disagree on, old value to new."

  def variations do
    [
      %Variation{
        id: :changed,
        description: "Only the metrics that differ are listed.",
        attributes: %{
          old: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
          new: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        }
      },
      %Variation{
        id: :same_base,
        description: "Vectors that agree on every base metric render nothing.",
        attributes: %{
          old: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
          new: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:A"
        }
      }
    ]
  end
end
