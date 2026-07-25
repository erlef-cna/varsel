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

  def entry("affected_package_form"), do: [name: "Affected package form", icon: {:local, "hero-cube"}]

  def entry("channel_table"), do: [name: "Channel table", icon: {:local, "hero-table-cells"}]

  def entry("case_content"), do: [name: "Case content", icon: {:local, "hero-document-text"}]

  def entry("card_section_header"), do: [name: "Card section header", icon: {:local, "hero-bars-2"}]

  def entry("channel_form"), do: [name: "Channel form", icon: {:local, "hero-truck"}]
  def entry("credit_form"), do: [name: "Credit form", icon: {:local, "hero-user"}]
  def entry("edit_actions"), do: [name: "Edit actions", icon: {:local, "hero-check"}]
  def entry("edit_mode_notice"), do: [name: "Edit mode notice", icon: {:local, "hero-pencil"}]
  def entry("impact_form"), do: [name: "Impact form", icon: {:local, "hero-tag"}]
  def entry("lifecycle_stepper"), do: [name: "Lifecycle stepper", icon: {:local, "hero-flag"}]
  def entry("markdown"), do: [name: "Markdown", icon: {:local, "hero-document-text"}]
  def entry("mode_pill"), do: [name: "Mode pill", icon: {:local, "hero-pencil"}]

  def entry("program_files"), do: [name: "Program files", icon: {:local, "hero-document-text"}]

  def entry("preset_package_form"), do: [name: "Preset package form", icon: {:local, "hero-sparkles"}]

  def entry("reference_form"), do: [name: "Reference form", icon: {:local, "hero-link"}]

  def entry("resolved_proposal_card"), do: [name: "Resolved proposal card", icon: {:local, "hero-check-badge"}]

  def entry("proposal_marks"), do: [name: "Proposal marks", icon: {:local, "hero-flag"}]
  def entry("row_actions"), do: [name: "Row actions", icon: {:local, "hero-ellipsis-horizontal"}]

  def entry("relative_timestamp"), do: [name: "Relative timestamp", icon: {:local, "hero-calendar-days"}]

  def entry("section_nav"), do: [name: "Section nav", icon: {:local, "hero-bars-3-bottom-left"}]
  def entry("suggestion_card"), do: [name: "Suggestion card", icon: {:local, "hero-light-bulb"}]

  def entry("suggestion_diff"), do: [name: "Suggestion diff", icon: {:local, "hero-arrows-right-left"}]

  def entry("validation_checklist"), do: [name: "Validation checklist", icon: {:local, "hero-check-circle"}]

  def entry("version_event_form"), do: [name: "Version event form", icon: {:local, "hero-flag"}]

  def entry("version_timeline"), do: [name: "Version timeline", icon: {:local, "hero-variable"}]

  def entry("weakness_form"), do: [name: "Weakness form", icon: {:local, "hero-shield-exclamation"}]
end
