# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.MonoChip do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.mono_chip/1

  def variations do
    [
      %Variation{
        id: :default,
        description: "A purl, chipped.",
        slots: ["pkg:hex/phoenix"]
      },
      %Variation{
        id: :with_title,
        description: "Globals pass through, so a truncated chip can carry its full value as a tooltip.",
        attributes: %{title: "pkg:otp/ssh@5.1.4.2"},
        slots: ["pkg:otp/ssh"]
      },
      %Variation{
        id: :small,
        description: "The size that rides along a line of text, next to a path.",
        attributes: %{size: :small},
        slots: ["ssh_sftpd:handle_op/4"]
      },
      %VariationGroup{
        id: :truncation,
        description:
          "At `:normal` the chip fills its column and truncates; the same chip at " <>
            "`:small` shrinks to its content instead.",
        template: """
        <div class="w-48 border border-dashed border-base-300 p-2">
          <.psb-variation/>
        </div>
        """,
        variations: [
          %Variation{
            id: :normal_truncated,
            attributes: %{title: "pkg:golang/github.com/example/a-long-module-path"},
            slots: ["pkg:golang/github.com/example/a-long-module-path"]
          },
          %Variation{
            id: :small_unbounded,
            attributes: %{size: :small},
            slots: ["pkg:golang/github.com/example/a-long-module-path"]
          }
        ]
      }
    ]
  end
end
