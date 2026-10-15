# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.UserToken do
  @moduledoc """
  The GitHub access token to act as a user with, and the sentence an action
  answers with when there is none.

  The token is the one the person's own GitHub sign-in stored on their
  identity, read with them as the actor. `Varsel.GitHub.Credentials` decides
  when a request runs with it. GitHub expires that token after eight hours.
  A token that is about to expire is first exchanged for a new one with the
  refresh token the sign-in stored
  (`Varsel.Accounts.UserIdentity.Changes.RefreshAccessToken`).
  """

  alias Varsel.Accounts
  alias Varsel.Accounts.User
  alias Varsel.Accounts.UserIdentity
  alias Varsel.Accounts.UserIdentity.Changes.RefreshAccessToken
  alias Varsel.Accounts.UserIdentity.Errors.GitHubUnreachable
  alias Varsel.Accounts.UserIdentity.Errors.RefreshFailed
  alias Varsel.Accounts.UserIdentity.Errors.RefreshRefused

  require Ash.Query
  require Logger

  @typedoc """
  Why no token is available:

  - `:no_github_identity`: the account has no GitHub identity.
  - `:unauthorized`: GitHub refused to refresh the stored token.
  - `:unreachable`: the refresh did not reach GitHub.
  - `{:oauth_error, text}`: GitHub answered the refresh with another OAuth
    error. `text` is GitHub's description of it, or its error code.
  - `:refresh_failed`: the refresh failed for another reason, which is
    logged.
  """
  @type reason ::
          :no_github_identity
          | :unauthorized
          | :unreachable
          | {:oauth_error, String.t()}
          | :refresh_failed

  @doc """
  The GitHub access token of `user`, valid for at least five more minutes
  unless GitHub gave it no expiry.
  """
  @spec fetch(User.t()) :: {:ok, String.t()} | {:error, reason()}
  def fetch(%User{} = user) do
    case identity(user) do
      nil -> {:error, :no_github_identity}
      identity -> token(identity, user)
    end
  end

  @doc """
  Whether `user` has a GitHub identity to act on GitHub with. It does not
  ask GitHub whether the stored token still works.
  """
  @spec linked?(User.t() | nil) :: boolean()
  def linked?(nil), do: false
  def linked?(%User{} = user), do: identity(user) != nil

  @doc """
  The sentence an action states, after its subject, when it has no token to
  act with, when GitHub answered `:unauthorized` to the one it has, or when
  the refresh of that token failed.
  """
  @spec message(reason()) :: String.t()
  def message(:no_github_identity), do: "needs your GitHub account linked"
  def message(:unauthorized), do: "needs you to sign in with GitHub again"
  def message(:unreachable), do: "could not reach GitHub"
  def message({:oauth_error, error}), do: "could not renew its GitHub access: #{error}"
  def message(:refresh_failed), do: "could not renew its GitHub access"

  defp identity(user) do
    github =
      UserIdentity
      |> Ash.Query.filter(strategy == "github")
      |> Ash.Query.load(:access_token)

    user
    |> Ash.load!([identities: github], actor: user)
    |> Map.fetch!(:identities)
    |> Enum.find(&is_binary(&1.access_token))
  end

  defp token(identity, user) do
    if RefreshAccessToken.due?(identity) do
      refresh(identity, user)
    else
      {:ok, identity.access_token}
    end
  end

  defp refresh(identity, user) do
    case Accounts.refresh_github_access_token(identity, actor: user, load: [:access_token]) do
      {:ok, identity} -> {:ok, identity.access_token}
      {:error, error} -> {:error, reason(error, identity)}
    end
  end

  defp reason(error, identity) do
    case Enum.find_value(errors(error), &known_reason/1) do
      nil ->
        Logger.warning("Refreshing the GitHub access token of identity #{identity.id} failed: #{inspect(error)}")

        :refresh_failed

      reason ->
        reason
    end
  end

  defp errors(%{errors: errors}) when is_list(errors), do: errors
  defp errors(error), do: [error]

  defp known_reason(%RefreshRefused{}), do: :unauthorized
  defp known_reason(%GitHubUnreachable{}), do: :unreachable

  defp known_reason(%RefreshFailed{error: error, description: description}), do: {:oauth_error, description || error}

  defp known_reason(_error), do: nil
end
