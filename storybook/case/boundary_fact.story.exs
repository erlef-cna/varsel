# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.BoundaryFact do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AffectedComponents.boundary_fact/1

  def layout, do: :one_column

  def description, do: "Where the flaw entered a product, or left it."

  def variations do
    [
      %Variation{
        id: :introduced,
        attributes: %{
          event: :introduced,
          reference: "84adefa331c4…",
          title: "84adefa331c4159d432d22840663c38f155cd4c1"
        },
        slots: [
          ~s(<:actions><span class="link link-hover text-primary">Edit</span><span class="link link-hover text-base-content/50">Remove</span></:actions>)
        ]
      },
      %Variation{
        id: :fixed,
        attributes: %{
          event: :fixed,
          reference: "c5210b42a9d3…",
          title: "c5210b42a9d3d96f3d25601942ce8122be0f3761"
        }
      },
      %Variation{
        id: :scoped,
        description:
          "A fact limited to one channel. Scoping is why two channels of the same product " <>
            "can disagree about when the flaw ended.",
        attributes: %{
          event: :fixed,
          reference: "7.0",
          scope: "pkg:otp/inets"
        }
      },
      %Variation{
        id: :with_note,
        description:
          "The note wraps under the fact rather than being clipped into a column — it is " <>
            "where an author explains a boundary a reviewer would otherwise reconstruct.",
        attributes: %{
          event: :introduced,
          reference: "84adefa331c4…",
          title: "84adefa331c4159d432d22840663c38f155cd4c1",
          note:
            "The path-handling rewrite landed across two commits; this is the earlier one, " <>
              "which is where the unchecked join was introduced. The follow-up only moved it " <>
              "into ssh_xfer, so dating the flaw from there would understate the range."
        }
      },
      %Variation{
        id: :muted,
        description: "A fact a pending suggestion would remove.",
        attributes: %{event: :fixed, reference: "c5210b42a9d3…", muted: true},
        slots: [
          ~s(<:badges><span class="badge badge-info badge-xs">removal proposed</span></:badges>)
        ]
      }
    ]
  end
end
