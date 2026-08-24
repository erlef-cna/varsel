# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Event.Changes.FanOut do
  @moduledoc """
  Records a `Varsel.Notifications.Notification` for every user in an event's
  audience, honouring each recipient's per-kind preferences and excluding the
  actor who raised the event.

  Runs `after_action` inside `:fan_out`'s own transaction: raising here rolls
  the `processed_at` stamp back, so Oban retries the event.
  """

  use Ash.Resource.Change

  alias Varsel.Accounts.User
  alias Varsel.Cases.CaseAssignment
  alias Varsel.Notifications
  alias Varsel.Notifications.Kind
  alias Varsel.Notifications.Preference

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn _changeset, event ->
      opts = Varsel.ObanContext.forward(context)

      result =
        event
        |> recipients(opts)
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
          {:ok, event}

        %Ash.BulkResult{errors: errors} ->
          raise "Failed to record notifications for event #{event.id}: #{inspect(errors)}"
      end
    end)
  end

  defp recipients(event, opts) do
    case Kind.audience(event.kind) do
      :pocs ->
        User
        |> Ash.Query.filter(role == :poc)
        |> Ash.read!(opts)

      :assigned ->
        CaseAssignment
        |> Ash.Query.filter(case_id == ^event.case_id)
        |> Ash.Query.load(:user)
        |> Ash.read!(opts)
        |> Enum.map(& &1.user)

      :recipient ->
        [Ash.get!(User, event.recipient_id, opts)]
    end
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
        case_id: event.case_id,
        vulnerability_report_id: event.vulnerability_report_id,
        email_requested: preference.email
      }
    end)
  end
end
