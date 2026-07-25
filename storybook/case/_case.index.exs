# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case do
  @moduledoc false
  use PhoenixStorybook.Index

  def folder_icon, do: {:local, "hero-folder-open"}
  def folder_index, do: 3
  def folder_name, do: "Case workspace"

  def entry("activity_feed"), do: [name: "Activity feed", icon: {:local, "hero-clock"}]
  def entry("avatar_disc"), do: [name: "Avatar disc", icon: {:local, "hero-user-circle"}]
  def entry("lifecycle_stepper"), do: [name: "Lifecycle stepper", icon: {:local, "hero-flag"}]
  def entry("markdown"), do: [name: "Markdown", icon: {:local, "hero-document-text"}]
  def entry("mode_pill"), do: [name: "Mode pill", icon: {:local, "hero-pencil"}]

  def entry("relative_timestamp"), do: [name: "Relative timestamp", icon: {:local, "hero-calendar-days"}]

  def entry("section_nav"), do: [name: "Section nav", icon: {:local, "hero-bars-3-bottom-left"}]
  def entry("suggestion_card"), do: [name: "Suggestion card", icon: {:local, "hero-light-bulb"}]

  def entry("suggestion_diff"), do: [name: "Suggestion diff", icon: {:local, "hero-arrows-right-left"}]

  def entry("version_timeline"), do: [name: "Version timeline", icon: {:local, "hero-variable"}]
end
