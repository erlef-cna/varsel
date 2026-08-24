# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Notifications do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-bell"}
  def folder_index, do: 8
  def folder_name, do: "Notifications"

  def entry("notification_bell"), do: [name: "Notification bell", icon: {:local, "hero-bell"}]

  def entry("notification_row"), do: [name: "Notification row", icon: {:local, "hero-list-bullet"}]
end
