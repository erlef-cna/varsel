# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInvite.Changes.DeliverInvite do
  @moduledoc """
  Sends the invite email once the row is stamped as sent.

  Delivery runs after the action, so a send failure rolls the stamp back and
  Oban retries the row rather than dropping the invite.
  """

  use Ash.Resource.Change

  alias Varsel.Notifications.Emails

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.after_action(changeset, fn _changeset, invite ->
      Emails.deliver_invite(invite)
      {:ok, invite}
    end)
  end
end
