# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.RevokeTokens do
  @moduledoc """
  Revokes every token issued to an account as it is deleted.

  Tokens live in their own table with no foreign key to users, so nothing
  removes them on its own. They would not authenticate anybody — the session
  lookup finds no account — but a live token for an account that no longer
  exists is the sort of thing that stays true until it isn't, so it goes with
  the account rather than lingering until it expires.

  On the destroy action itself, so it holds for every caller: the settings
  page, the console's user list, or anything else that deletes an account
  later.
  """

  use Ash.Resource.Change

  alias AshAuthentication.Info
  alias AshAuthentication.TokenResource

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      revoke_all(changeset.data, context)
      changeset
    end)
  end

  defp revoke_all(user, context) do
    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(user.__struct__),
         {:ok, action} <-
           TokenResource.Info.token_revocation_revoke_all_stored_for_subject_action_name(token_resource) do
      Ash.bulk_update(
        token_resource,
        action,
        %{subject: AshAuthentication.user_to_subject(user)},
        Ash.Context.to_opts(context,
          strategy: [:atomic, :atomic_batches, :stream],
          context: %{private: %{ash_authentication?: true}},
          return_errors?: true,
          stop_on_error?: true
        )
      )
    end

    :ok
  end
end
