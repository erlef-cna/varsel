# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-squares-2x2"}
  def folder_index, do: 1
  def folder_name, do: "Core"
  def folder_open?, do: true

  def entry("button"), do: [name: "Button", icon: {:local, "hero-cursor-arrow-rays"}]
  def entry("code_block"), do: [name: "Code block", icon: {:local, "hero-code-bracket"}]
  def entry("modal"), do: [name: "Modal", icon: {:local, "hero-window"}]
  def entry("mono_chip"), do: [name: "Mono chip", icon: {:local, "hero-command-line"}]
  def entry("page_container"), do: [name: "Page container", icon: {:local, "hero-view-columns"}]
  def entry("page_header"), do: [name: "Page header", icon: {:local, "hero-window"}]

  def entry("console_search"), do: [name: "Console search", icon: {:local, "hero-magnifying-glass"}]

  def entry("count_label"), do: [name: "Count label", icon: {:local, "hero-hashtag"}]
  def entry("empty_state"), do: [name: "Empty state", icon: {:local, "hero-inbox"}]
  def entry("header"), do: [name: "Header", icon: {:local, "hero-bars-3-bottom-left"}]
  def entry("icon"), do: [name: "Icon", icon: {:local, "hero-sparkles"}]
  def entry("input"), do: [name: "Input", icon: {:local, "hero-pencil-square"}]
  def entry("flash"), do: [name: "Flash", icon: {:local, "hero-bell-alert"}]

  def entry("pagination"), do: [name: "Pagination", icon: {:local, "hero-chevron-double-right"}]

  def entry("list"), do: [name: "List", icon: {:local, "hero-list-bullet"}]
  def entry("list_card"), do: [name: "List card", icon: {:local, "hero-rectangle-stack"}]
  def entry("panel"), do: [name: "Panel", icon: {:local, "hero-rectangle-group"}]

  def entry("scope_tab"), do: [name: "Scope tab", icon: {:local, "hero-funnel"}]

  def entry("severity_chip"), do: [name: "Severity chip", icon: {:local, "hero-shield-exclamation"}]

  def entry("stat_tiles"), do: [name: "Stat tiles", icon: {:local, "hero-chart-bar-square"}]
  def entry("state"), do: [name: "State", icon: {:local, "hero-signal"}]
  def entry("tab_bar"), do: [name: "Tab bar", icon: {:local, "hero-rectangle-stack"}]
  def entry("table"), do: [name: "Table", icon: {:local, "hero-table-cells"}]

  def entry("table_of_contents"), do: [name: "Table of contents", icon: {:local, "hero-bars-3"}]
end
