# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Root do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-book-open"}
  def folder_name, do: "Varsel UI"

  def entry("welcome"), do: [name: "Welcome", icon: {:local, "hero-hand-raised"}, index: 0]
end
