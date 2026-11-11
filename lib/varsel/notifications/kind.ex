# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Kind do
  @moduledoc """
  The events a notification can be raised for.

  `audience/1` says who a kind is fanned out to; `label/1` gives the short
  sentence fragment the bell, the notifications page and notification
  emails render it as.
  """

  use Ash.Type.Enum,
    values: [
      report_submitted: [
        label: "New vulnerability report",
        description: "A vulnerability report was submitted."
      ],
      review_requested: [
        label: "Review requested",
        description: "A case was handed to review."
      ],
      comment_posted: [
        label: "New comment",
        description: "A comment was posted on a case."
      ],
      mentioned: [
        label: "Mentioned",
        description: "Someone mentioned you in a comment on a case."
      ],
      proposal_opened: [
        label: "New proposal",
        description: "A proposal was opened on a case."
      ],
      case_published: [
        label: "Case published",
        description: "A case was published as a CVE record."
      ],
      case_assigned: [
        label: "Added to a case",
        description: "A user was granted access to a case."
      ]
    ]

  @doc """
  Who a kind's notifications are fanned out to. `:reviewers` are the POCs
  assigned to the case, or every POC when none is.
  """
  @spec audience(t()) :: :pocs | :reviewers | :assigned | :recipient | :mentioned
  def audience(:report_submitted), do: :pocs
  def audience(:review_requested), do: :reviewers
  def audience(:comment_posted), do: :assigned
  def audience(:mentioned), do: :mentioned
  def audience(:proposal_opened), do: :assigned
  def audience(:case_published), do: :assigned
  def audience(:case_assigned), do: :recipient
end
