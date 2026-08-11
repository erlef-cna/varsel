# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.DerivationMarker do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AffectedComponents.derivation_marker/1

  def layout, do: :one_column

  def description, do: "Which product is behind, when the case-wide status is reported elsewhere."

  @template """
  <div class="flex items-center gap-3 text-[0.68rem] font-bold uppercase tracking-wider text-base-content/60">
    Affected — Erlang / OTP <.psb-variation/>
  </div>
  """

  def variations do
    [
      %Variation{
        id: :outdated,
        description: "The product whose facts moved after the case last derived.",
        template: @template,
        attributes: %{state: :outdated}
      },
      %Variation{
        id: :never,
        description: "A product added since the last derivation, which has none of its own yet.",
        template: @template,
        attributes: %{state: :never}
      },
      %Variation{
        id: :current,
        description:
          "Nothing renders. A case is usually all-current, and a row of \"fine\" marks would " <>
            "say nothing while costing a reader the effort of checking each one.",
        template: @template,
        attributes: %{state: :current}
      },
      %Variation{
        id: :ageing,
        description: "Also silent — ageing is the case's business, not this product's.",
        template: @template,
        attributes: %{state: :ageing}
      }
    ]
  end
end
