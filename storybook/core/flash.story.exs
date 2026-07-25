# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Flash do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.flash/1

  def layout, do: :one_column

  # Flashes are `position: fixed` toasts pinned to the viewport's top-right, so
  # in a story they escape their variation and stack in the page corner.
  # `psb-fixed-contained` (storybook.css) transforms the box into the
  # containing block for fixed descendants, keeping each toast in its own
  # variation. The height reserves the room the toast then occupies.
  def container, do: {:div, class: "psb-fixed-contained w-full h-20"}

  def variations do
    [
      %Variation{
        id: :info,
        attributes: %{kind: :info},
        slots: ["Case submitted for review."]
      },
      %Variation{
        id: :error,
        attributes: %{kind: :error},
        slots: ["Could not reach the MITRE API. Try again in a moment."]
      },
      %Variation{
        id: :with_title,
        attributes: %{kind: :error, title: "Something went wrong!"},
        slots: ["Attempting to reconnect…"]
      },
      %Variation{
        id: :long_message,
        description: "Long copy wraps inside the toast's fixed width.",
        attributes: %{kind: :info, title: "Publication queued"},
        slots: [
          """
          The record was handed to the publisher and will be submitted to MITRE
          shortly. You will get an email when the CVE ID goes live.
          """
        ]
      }
    ]
  end
end
