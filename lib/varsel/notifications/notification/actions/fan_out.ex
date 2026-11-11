# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Notification.Actions.FanOut do
  @moduledoc """
  Records a `Varsel.Notifications.Notification` for every user in a signal's
  audience, honouring each recipient's per-kind preferences and excluding the
  user who acted. A mention reaches only the mentioned who may read the case,
  and a review a POC requested reaches nobody. A review on a case with no POC
  assigned is an `:unassigned_review_requested` for the POCs who want one,
  or a plain `:review_requested` for every POC while none does.

  Implements `Varsel.Notifications.Notification`'s `:fan_out` action, the
  listener of every signal that raises a notification. A failure raises, so
  the action's transaction records nothing and Oban retries the signal.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.Accounts.User
  alias Varsel.Cases
  alias Varsel.Cases.CaseAssignment
  alias Varsel.Notifications
  alias Varsel.Notifications.Kind
  alias Varsel.Notifications.Preference

  require Ash.Query

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    opts = Varsel.ObanContext.forward(context)
    {event, recipients} = input.arguments.signal |> event() |> route(opts)

    result =
      recipients
      |> inputs(event)
      |> Notifications.record_notification(
        Keyword.put(opts, :bulk_options,
          notify?: true,
          return_errors?: true,
          stop_on_error?: true
        )
      )

    case result do
      %Ash.BulkResult{status: :success} ->
        :ok

      %Ash.BulkResult{errors: errors} ->
        raise "Failed to record #{event.kind} notifications: #{inspect(errors)}"
    end
  end

  defp event(%Cases.Signals.ReportSubmitted{} = signal),
    do: %{kind: :report_submitted, case_id: signal.case_id, actor_id: signal.actor_id}

  defp event(%Cases.Signals.ReviewRequested{} = signal),
    do: %{kind: :review_requested, case_id: signal.case_id, actor_id: signal.actor_id}

  defp event(%Cases.Signals.CasePublished{} = signal),
    do: %{kind: :case_published, case_id: signal.case_id, actor_id: signal.actor_id}

  defp event(%Cases.Signals.CommentPosted{} = signal),
    do: %{kind: :comment_posted, case_id: signal.case_id, actor_id: signal.actor_id}

  defp event(%Cases.Signals.UsersMentioned{} = signal),
    do: %{kind: :mentioned, case_id: signal.case_id, recipient_ids: signal.user_ids, actor_id: signal.actor_id}

  defp event(%Cases.Signals.ProposalOpened{} = signal),
    do: %{kind: :proposal_opened, case_id: signal.case_id, actor_id: signal.actor_id}

  defp event(%Cases.Signals.CaseAssigned{} = signal),
    do: %{kind: :case_assigned, case_id: signal.case_id, recipient_id: signal.user_id, actor_id: signal.actor_id}

  defp route(%{kind: :review_requested} = event, opts) do
    if requested_by_poc?(event.actor_id, opts), do: {event, []}, else: route_review(event, opts)
  end

  defp route(event, opts), do: {event, audience(event, opts)}

  # A coordinator often cannot assign a POC, so a case with none must still
  # reach a reviewer.
  defp route_review(event, opts) do
    case audience(event, opts) do
      [] ->
        unassigned = %{event | kind: :unassigned_review_requested}
        pocs = audience(unassigned, opts)

        if Enum.any?(pocs, &in_app?(&1, unassigned.kind)),
          do: {unassigned, pocs},
          else: {event, pocs}

      assigned_pocs ->
        {event, assigned_pocs}
    end
  end

  defp in_app?(user, kind), do: Preference.for_kind(user.notification_preferences, kind).in_app

  defp requested_by_poc?(nil, _opts), do: false

  defp requested_by_poc?(actor_id, opts) do
    match?({:ok, %User{role: :poc}}, Ash.get(User, actor_id, opts))
  end

  defp audience(event, opts) do
    case Kind.audience(event.kind) do
      :pocs ->
        User
        |> Ash.Query.filter(role == :poc)
        |> Ash.read!(opts)

      :reviewers ->
        event |> assigned_users(opts) |> Enum.filter(&(&1.role == :poc))

      :assigned ->
        assigned_users(event, opts)

      :recipient ->
        [Ash.get!(User, event.recipient_id, opts)]

      # A comment names whoever its writer typed, so only the mentioned who
      # can read the case hear about it.
      :mentioned ->
        assigned =
          CaseAssignment
          |> Ash.Query.filter(case_id == ^event.case_id and user_id in ^event.recipient_ids)
          |> Ash.read!(opts)
          |> Enum.map(& &1.user_id)

        User
        |> Ash.Query.filter(id in ^event.recipient_ids and (role == :poc or id in ^assigned))
        |> Ash.read!(opts)
    end
  end

  defp assigned_users(event, opts) do
    CaseAssignment
    |> Ash.Query.filter(case_id == ^event.case_id)
    |> Ash.Query.load(:user)
    |> Ash.read!(opts)
    |> Enum.map(& &1.user)
  end

  defp inputs(users, event) do
    users
    |> Enum.reject(&(&1.id == event.actor_id))
    |> Enum.map(&{&1, Preference.for_kind(&1.notification_preferences, event.kind)})
    |> Enum.filter(fn {_user, preference} -> preference.in_app end)
    |> Enum.map(fn {user, preference} ->
      %{
        kind: event.kind,
        user_id: user.id,
        case_id: event[:case_id],
        email_requested: preference.email
      }
    end)
  end
end
