# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.User do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-user-circle"}
  def folder_index, do: 6
  def folder_name, do: "User"

  def entry("avatar_disc"), do: [name: "Avatar disc", icon: {:local, "hero-user-circle"}]
end
