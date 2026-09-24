# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Notification.Changes.DeliverImmediate do
  @moduledoc """
  Sends the immediate notification email once the row is stamped as emailed.

  Delivery runs after the action, so a send failure rolls the stamp back and
  Oban retries the row rather than dropping the email.
  """

  use Ash.Resource.Change

  alias Varsel.Notifications.Emails

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn _changeset, notification ->
      Emails.deliver_immediate(notification, context)
      {:ok, notification}
    end)
  end
end
