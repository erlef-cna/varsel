# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.MockGenerateToken do
  @moduledoc """
  Puts a freshly signed session token in the result's metadata so
  `AshAuthentication.Plug.Helpers.store_in_session/2` can log the mock user in.

  `AshAuthentication.GenerateTokenChange` is not usable here because it
  resolves a strategy from the action, and the mock sign-in belongs to no
  strategy. `Jwt.token_for_user/2` also persists the token to the token
  resource, which `require_token_presence_for_authentication?` demands.

  Lives under `dev/`, which is only compiled for `:dev` and `:test`.
  """

  use Ash.Resource.Change

  alias AshAuthentication.Jwt

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn _changeset, user ->
      case Jwt.token_for_user(user, %{}, Ash.Context.to_opts(context)) do
        {:ok, token, _claims} -> {:ok, Ash.Resource.put_metadata(user, :token, token)}
        {:error, error} -> {:error, error}
      end
    end)
  end
end
