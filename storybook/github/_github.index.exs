# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.GitHub do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-code-bracket-square"}
  def folder_index, do: 9
  def folder_name, do: "GitHub"

  def entry("github_installation_list"), do: [name: "Installation list", icon: {:local, "hero-building-office-2"}]
end
