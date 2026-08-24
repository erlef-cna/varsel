# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Notifier do
  @moduledoc """
  Ash notifier that raises a `Varsel.Notifications.Event` for the actions the
  notification system cares about, attached to each source resource.

  Runs after the source action's transaction commits, as
  `Varsel.Service.notifier/0`, the only actor
  `Varsel.Notifications.Event`'s `:emit` policy authorizes.
  """

  use Ash.Notifier

  alias Ash.Notifier.Notification
  alias Varsel.Accounts.User
  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseAssignment
  alias Varsel.Cases.Comment
  alias Varsel.Cases.Proposal
  alias Varsel.CVE.VulnerabilityReport
  alias Varsel.Notifications
  alias Varsel.Service

  require Logger

  @impl Ash.Notifier
  def notify(%Notification{resource: VulnerabilityReport, action: %{name: name}, data: report, actor: actor})
      when name in [:submit, :submit_from_hex] do
    emit(:report_submitted, actor, vulnerability_report_id: report.id)
  end

  def notify(%Notification{resource: Comment, action: %{name: :post}, data: comment, actor: actor}) do
    emit(:comment_posted, actor, case_id: comment.case_id)
  end

  def notify(%Notification{resource: Proposal, action: %{type: :create}, data: proposal, actor: actor}) do
    emit(:proposal_opened, actor, case_id: proposal.case_id)
  end

  def notify(%Notification{resource: Case, action: %{name: :request_review}, data: case_record, actor: actor}) do
    emit(:review_requested, actor, case_id: case_record.id)
  end

  def notify(%Notification{resource: Case, action: %{name: :mark_published}, data: case_record, actor: actor}) do
    emit(:case_published, actor, case_id: case_record.id)
  end

  # Self-assignment (Case.open assigning its own opener) has nothing to tell
  # the assignee that they do not already know, so it raises no event.
  def notify(%Notification{
        resource: CaseAssignment,
        action: %{name: :assign},
        actor: %User{id: id},
        data: %{user_id: id}
      }) do
    :ok
  end

  def notify(%Notification{resource: CaseAssignment, action: %{name: :assign}, data: assignment, actor: actor}) do
    emit(:case_assigned, actor, case_id: assignment.case_id, recipient_id: assignment.user_id)
  end

  def notify(_notification), do: :ok

  defp emit(kind, actor, attrs) do
    input = Enum.into(attrs, %{kind: kind, actor_id: actor_id(actor)})

    case Notifications.emit_notification_event(input, actor: Service.notifier()) do
      {:ok, _event} ->
        :ok

      {:error, error} ->
        Logger.error("Failed to emit notification event #{kind}: #{Exception.message(error)}")
        :ok
    end
  end

  defp actor_id(%User{id: id}), do: id
  defp actor_id(_actor), do: nil
end
