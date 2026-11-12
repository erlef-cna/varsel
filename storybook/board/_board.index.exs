# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Board do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-view-columns"}
  def folder_index, do: 2
  def folder_name, do: "Board"

  def entry("matrix"), do: [name: "Matrix", icon: {:local, "hero-table-cells"}]
  def entry("card"), do: [name: "Card", icon: {:local, "hero-document"}]
end
