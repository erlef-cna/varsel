# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Cve do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-shield-exclamation"}
  def folder_index, do: 2
  def folder_name, do: "CVE"
  def folder_open?, do: true

  def entry("affected_range_list"), do: [name: "Affected range list", icon: {:local, "hero-bars-arrow-down"}]

  def entry("package_display_name"), do: [name: "Package display name", icon: {:local, "hero-cube"}]
end
