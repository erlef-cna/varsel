# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.ConsoleSearch do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.console_search/1

  # The input is named `query` and expects an enclosing phx-change form.
  def template do
    """
    <form phx-change="search" psb-code-hidden>
      <.psb-variation/>
    </form>
    """
  end

  def variations do
    [
      %Variation{
        id: :empty,
        attributes: %{value: "", placeholder: "Search cases…"}
      },
      %Variation{
        id: :with_query,
        attributes: %{value: "CVE-2026-1234", placeholder: "Search cases…"}
      },
      %Variation{
        id: :cve_list,
        description: "The public CVE list's copy.",
        attributes: %{value: "", placeholder: "Search by CVE ID, package or title…"}
      }
    ]
  end
end
