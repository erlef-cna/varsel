# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.TlpChip do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.tlp_chip/1

  def variations do
    [
      %VariationGroup{
        id: :labels,
        description: "Every TLP 2.0 label, from the most to the least restricted.",
        variations: [
          %Variation{id: :red, attributes: %{label: :red}},
          %Variation{id: :amber_strict, attributes: %{label: :amber_strict}},
          %Variation{id: :amber, attributes: %{label: :amber}},
          %Variation{id: :green, attributes: %{label: :green}},
          %Variation{id: :clear, attributes: %{label: :clear}}
        ]
      },
      %Variation{
        id: :caveat,
        description: "A caveat adds the `+CAVEAT` suffix, and the hover card shows its text.",
        attributes: %{label: :green, caveat: "The community is the EEF security working group."}
      },
      %Variation{
        id: :no_info,
        description: "`info={false}` drops the hover card, where the text is already next to the chip.",
        attributes: %{label: :amber, info: false}
      }
    ]
  end
end
