# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.CopyButton do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.copy_button/1

  def layout, do: :one_column

  def description, do: "Copies a value to the clipboard, confirming on itself."

  def variations do
    [
      %Variation{
        id: :default,
        description: "Resting.",
        attributes: %{value: "CVE-2026-90116", label: "Copy CVE-2026-90116"}
      },
      %Variation{
        id: :copied,
        description: "After a copy. Held by its class; a real click clears it after 1.5s.",
        attributes: %{
          value: "CVE-2026-90116",
          label: "Copy CVE-2026-90116",
          class: "is-copied"
        }
      },
      %Variation{
        id: :failed,
        description: "The copy was refused — nothing reached the clipboard.",
        attributes: %{
          value: "CVE-2026-90116",
          label: "Copy CVE-2026-90116",
          class: "is-copy-failed"
        }
      }
    ]
  end
end
