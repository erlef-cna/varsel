# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.AdvisoryAudience do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AdvisoryComponents.advisory_audience/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  @audience %{
    users: ["garazdawi"],
    teams: [%{slug: "security", members: ["kikofernandez", "IngelaAndin"]}],
    owners: ["maennchen"]
  }

  def variations do
    [
      %Variation{
        id: :resolved,
        description: "Everyone resolved. Two are on the case, and the viewer may give the rest access.",
        attributes: %{
          audience: @audience,
          on_case: %{"garazdawi" => :assigned, "ingelaandin" => :invited},
          can_grant: true
        }
      },
      %Variation{
        id: :read_only,
        description: "A viewer who may not grant access sees who is there.",
        attributes: %{audience: @audience, on_case: %{"garazdawi" => :assigned}}
      },
      %Variation{
        id: :unreadable,
        description: "The viewer's GitHub account is no member of the organization.",
        attributes: %{
          audience: %{
            users: [],
            teams: [%{slug: "security", members: :unknown}],
            owners: :unknown
          },
          on_case: %{},
          can_grant: true
        }
      },
      %Variation{
        id: :loading,
        description: "While GitHub is asked.",
        attributes: %{loading: true}
      }
    ]
  end
end
