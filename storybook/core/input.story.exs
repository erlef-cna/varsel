# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Input do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.input/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full max-w-lg"}

  def variations do
    [
      %VariationGroup{
        id: :types,
        description: "Every input type shares the same label/description/error frame.",
        variations: [
          %Variation{
            id: :text,
            attributes: %{name: "title", value: "Heap overflow in the packet parser"},
            slots: ["<:label>Title</:label>"]
          },
          %Variation{
            id: :textarea,
            attributes: %{
              type: "textarea",
              name: "description",
              rows: 3,
              value: "A remote attacker can crash the node by sending a malformed frame."
            },
            slots: ["<:label>Description</:label>"]
          },
          %Variation{
            id: :select,
            attributes: %{
              type: "select",
              name: "state",
              value: "review",
              options: [{"Draft", "draft"}, {"Review", "review"}, {"Approved", "approved"}]
            },
            slots: ["<:label>State</:label>"]
          },
          %Variation{
            id: :checkbox,
            attributes: %{type: "checkbox", name: "notify", value: true},
            slots: ["<:label>Email the reporter when this publishes</:label>"]
          },
          %Variation{
            id: :date,
            attributes: %{type: "date", name: "published_on", value: "2026-06-12"},
            slots: ["<:label>Publication date</:label>"]
          },
          %Variation{
            id: :email,
            attributes: %{type: "email", name: "email", value: "", placeholder: "you@example.com"},
            slots: ["<:label>Contact email</:label>"]
          }
        ]
      },
      %Variation{
        id: :with_description,
        description: "The `:description` slot renders small and muted under the field.",
        attributes: %{name: "purl", value: "pkg:hex/rabbit_common"},
        slots: [
          "<:label>Package URL</:label>",
          "<:description>A <code>purl</code> identifying the affected package.</:description>"
        ]
      },
      %Variation{
        id: :with_errors,
        description: "Errors tint the control and list below it.",
        attributes: %{
          name: "cve_id",
          value: "CVE-nope",
          errors: ["is not a valid CVE ID"]
        },
        slots: ["<:label>CVE ID</:label>"]
      },
      %Variation{
        id: :select_with_errors,
        attributes: %{
          type: "select",
          name: "state",
          value: nil,
          prompt: "Choose a state…",
          options: [{"Draft", "draft"}, {"Review", "review"}],
          errors: ["can't be blank"]
        },
        slots: ["<:label>State</:label>"]
      },
      %Variation{
        id: :rich_label,
        description: "The label is a slot, so it takes links and markup.",
        attributes: %{name: "cvss_v4", value: ""},
        slots: [
          """
          <:label>
            CVSS v4.0 vector
            <a class="link link-primary" href="https://www.first.org/cvss/calculator/4.0" target="_blank" rel="noopener">calculator</a>
          </:label>
          """
        ]
      },
      %Variation{
        id: :disabled,
        attributes: %{name: "cve_id", value: "CVE-2026-1234", disabled: true},
        slots: [
          "<:label>CVE ID</:label>",
          "<:description>Assigned — cannot be changed.</:description>"
        ]
      }
    ]
  end
end
