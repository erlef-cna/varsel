# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.UserToken do
  @moduledoc """
  The GitHub access token to act as a user with, and the sentence an action
  answers with when there is none.

  Varsel acts on GitHub only as the person asking, so the token is the one
  their own GitHub sign-in stored on their identity, read with them as the
  actor.
  """

  alias Varsel.Accounts.User

  @typedoc "Why no token is available: the account has no GitHub identity."
  @type reason :: :no_github_identity

  @doc "The GitHub access token of `user`."
  @spec fetch(User.t()) :: {:ok, String.t()} | {:error, reason()}
  def fetch(%User{} = user) do
    user = Ash.load!(user, :identities, actor: user)

    case Enum.find(user.identities, &(&1.strategy == "github")) do
      %{access_token: token} when is_binary(token) -> {:ok, token}
      _none -> {:error, :no_github_identity}
    end
  end

  @doc "Whether `user` has a GitHub identity to act on GitHub with."
  @spec linked?(User.t() | nil) :: boolean()
  def linked?(nil), do: false
  def linked?(%User{} = user), do: match?({:ok, _token}, fetch(user))

  @doc """
  The sentence an action states, after its subject, when it has no token to
  act with, or when GitHub answered `:unauthorized` to the one it has.
  """
  @spec message(reason() | :unauthorized) :: String.t()
  def message(:no_github_identity), do: "needs your GitHub account linked"
  def message(:unauthorized), do: "needs you to sign in with GitHub again"
end
