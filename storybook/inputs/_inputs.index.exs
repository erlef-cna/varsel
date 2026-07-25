# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Inputs do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-pencil-square"}
  def folder_index, do: 3
  def folder_name, do: "Inputs"

  def entry("cvss_input"), do: [name: "CVSS input", icon: {:local, "hero-calculator"}]
  def entry("markdown_input"), do: [name: "Markdown input", icon: {:local, "hero-document-text"}]
end
