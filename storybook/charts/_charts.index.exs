# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Charts do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-chart-pie"}
  def folder_index, do: 7
  def folder_name, do: "Charts"

  def entry("cwe_donut"), do: [name: "CWE donut", icon: {:local, "hero-chart-pie"}]
  def entry("cwe_legend"), do: [name: "CWE legend", icon: {:local, "hero-list-bullet"}]
end
