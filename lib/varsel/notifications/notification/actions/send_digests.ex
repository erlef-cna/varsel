# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Notification.Actions.SendDigests do
  @moduledoc """
  Sends the daily digest email to every user who asked for one.

  Implements `Varsel.Notifications.Notification`'s `:send_digests` action. A
  failed digest does not stop the others: the run collects every error and
  raises at the end, so Oban retries the whole sweep.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.Accounts.User
  alias Varsel.Notifications.Emails
  alias Varsel.Notifications.Notification

  require Ash.Query

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    opts = Varsel.ObanContext.forward(context)

    errors = Enum.flat_map(digest_user_ids(opts), &send_digest(&1, opts, context))

    if errors == [] do
      {:ok, :ok}
    else
      raise "Failed to send notification digests: #{inspect(errors)}"
    end
  end

  defp digest_user_ids(opts) do
    User
    |> Ash.Query.filter(
      notification_email_mode == :daily_digest and
        exists(notifications, email_requested and is_nil(emailed_at) and is_nil(read_at))
    )
    |> Ash.Query.select([:id])
    |> Ash.read!(opts)
    |> Enum.map(& &1.id)
  end

  defp send_digest(user_id, opts, context) do
    pending =
      Notification
      |> Ash.Query.filter(
        user_id == ^user_id and email_requested and is_nil(emailed_at) and
          is_nil(read_at)
      )
      |> Ash.read!(opts)

    Emails.deliver_digest(user_id, pending, context)

    bulk_opts = Keyword.merge(opts, notify?: true, return_errors?: true)

    case Ash.bulk_update(pending, :mark_emailed, %{}, bulk_opts) do
      %Ash.BulkResult{status: :success} -> []
      %Ash.BulkResult{errors: errors} -> errors
    end
  end
end
