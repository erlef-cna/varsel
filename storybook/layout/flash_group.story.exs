# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Layout.FlashGroup do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.Layouts.flash_group/1

  def layout, do: :one_column

  # Same fixed-position containment as the Flash story — see storybook.css.
  def container, do: {:div, class: "psb-fixed-contained w-full h-24"}

  def variations do
    [
      %Variation{
        id: :empty,
        description: """
        The group every layout renders. It holds the `:info` and `:error`
        slots plus two connection banners that stay hidden until LiveView
        reports a dropped socket — with no flash set, nothing shows.
        """,
        attributes: %{flash: %{}}
      },
      %Variation{
        id: :info,
        attributes: %{flash: %{"info" => "Case submitted for review."}}
      },
      %Variation{
        id: :error,
        attributes: %{flash: %{"error" => "Could not reach the MITRE API."}}
      },
      %Variation{
        id: :both,
        description: "Info and error stack in the same corner.",
        attributes: %{
          flash: %{
            "info" => "Draft saved.",
            "error" => "The CVSS vector is not valid."
          }
        }
      }
    ]
  end
end
