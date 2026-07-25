# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.List do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.list/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :default,
        description: "A title/value data list — used on record detail pages.",
        slots: [
          ~s|<:item title="CVE ID"><span class="font-mono">CVE-2026-1234</span></:item>|,
          ~s|<:item title="State">Published</:item>|,
          ~s|<:item title="Published">12 June 2026</:item>|
        ]
      },
      %Variation{
        id: :single_item,
        slots: [~s|<:item title="Assigned to">Alex Rivera</:item>|]
      },
      %Variation{
        id: :rich_values,
        description: "Values take markup, not just text.",
        slots: [
          """
          <:item title="Severity">
            <span class="font-mono">CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N</span>
          </:item>
          """,
          ~s|<:item title="References"><a class="link link-primary" href="#">GHSA-xxxx-yyyy-zzzz</a></:item>|
        ]
      }
    ]
  end
end
