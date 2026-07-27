# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Changes.RefuseLastIdentity do
  @moduledoc """
  Refuses to unlink the only provider an account has left.

  Providers are the only way to sign in, so removing the last one locks the
  account permanently — there is no password to fall back to, and attaching a
  replacement needs a session you could no longer get. API keys authenticate
  requests, not the browser session that linking requires.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, &refuse_if_last(&1, context))
  end

  defp refuse_if_last(changeset, context) do
    if last_identity?(changeset, context) do
      Ash.Changeset.add_error(changeset,
        field: :strategy,
        message: "is the only way to sign in to this account, so it cannot be unlinked"
      )
    else
      changeset
    end
  end

  # Counts through the owning user, whose own policy already let the actor
  # reach this row — `accessing_from` covers the identities read.
  defp last_identity?(changeset, context) do
    siblings =
      changeset.data
      |> Ash.load!([user: [:identities]], Ash.Context.to_opts(context))
      |> Map.fetch!(:user)
      |> Map.fetch!(:identities)

    length(siblings) <= 1
  end
end
