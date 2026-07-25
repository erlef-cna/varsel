# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Layout do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-window"}
  def folder_index, do: 4
  def folder_name, do: "Layout"

  def entry("eef_logo"), do: [name: "EEF logo", icon: {:local, "hero-identification"}]
  def entry("flash_group"), do: [name: "Flash group", icon: {:local, "hero-bell-alert"}]
  def entry("site_footer"), do: [name: "Site footer", icon: {:local, "hero-bars-3-bottom-right"}]
  def entry("site_nav"), do: [name: "Site nav", icon: {:local, "hero-bars-3"}]
  def entry("theme_toggle"), do: [name: "Theme toggle", icon: {:local, "hero-sun"}]
end
