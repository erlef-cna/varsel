# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Kind do
  @moduledoc """
  The events a notification can be raised for.

  `audience/1` says who a kind is fanned out to; `label/1` gives the short
  sentence fragment the bell, the notifications page and notification
  emails render it as; `on_by_default?/1` whether a user hears of it before
  choosing.
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
      unassigned_review_requested: [
        label: "Unassigned review",
        description: "A user requested a review on a case with no POC assigned."
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
  assigned to the case.
  """
  @spec audience(t()) :: :pocs | :reviewers | :assigned | :recipient | :mentioned
  def audience(:report_submitted), do: :pocs
  def audience(:review_requested), do: :reviewers
  def audience(:unassigned_review_requested), do: :pocs
  def audience(:comment_posted), do: :assigned
  def audience(:mentioned), do: :mentioned
  def audience(:proposal_opened), do: :assigned
  def audience(:case_published), do: :assigned
  def audience(:case_assigned), do: :recipient

  @doc """
  Whether a kind reaches a user who has not chosen for it. A review on a case
  with no POC is opt-in: a POC asks for it, and while none does every POC
  gets it as a plain review request.
  """
  @spec on_by_default?(t()) :: boolean()
  def on_by_default?(:unassigned_review_requested), do: false
  def on_by_default?(_kind), do: true
end
