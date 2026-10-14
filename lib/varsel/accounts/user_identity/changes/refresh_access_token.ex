# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Changes.RefreshAccessToken do
  @moduledoc """
  Exchanges a GitHub identity's refresh token for a new access token when
  the stored access token is `due?/1`, and stores the tokens GitHub answers
  with.

  GitHub accepts a refresh token only once. The change therefore decides on
  the row as `get_and_lock_for_update()` re-read it inside the transaction.
  A second refresh of the same identity waits for that lock and then finds
  the token the first refresh stored.

  The client credentials and token endpoint are those of the `:github`
  sign-in strategy on `Varsel.Accounts.User`.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias AshAuthentication.Errors.MissingSecret
  alias Assent.ServerUnreachableError
  alias Assent.Strategy.OAuth2
  alias Varsel.Accounts.User
  alias Varsel.Accounts.UserIdentity.Errors.GitHubUnreachable
  alias Varsel.Accounts.UserIdentity.Errors.RefreshFailed
  alias Varsel.Accounts.UserIdentity.Errors.RefreshRefused

  @margin_seconds 5 * 60

  # GitHub answers a refused refresh with HTTP 200 and an `error` field, and
  # names a spent or expired refresh token `bad_refresh_token`.
  @refused ~w(bad_refresh_token invalid_grant)

  @doc """
  Whether the access token of `identity` expires within five minutes or has
  expired. A token without an expiry is never due.
  """
  @spec due?(Ash.Resource.Record.t()) :: boolean()
  def due?(%{access_token_expires_at: nil}), do: false

  def due?(%{access_token_expires_at: expires_at}), do: DateTime.diff(expires_at, DateTime.utc_now()) < @margin_seconds

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.before_action(changeset, &refresh(&1, context))
  end

  defp refresh(%{data: identity} = changeset, context) do
    if due?(identity) do
      with {:ok, refresh_token} <- refresh_token(identity, context),
           {:ok, token} <- exchange(refresh_token) do
        store(changeset, token, refresh_token, context)
      else
        {:error, error} -> Changeset.add_error(changeset, error)
      end
    else
      changeset
    end
  end

  defp refresh_token(identity, context) do
    case Ash.load(
           identity,
           :refresh_token,
           Keyword.put(Ash.Context.to_opts(context), :reuse_values?, true)
         ) do
      {:ok, %{refresh_token: nil}} ->
        {:error, RefreshRefused.exception(reason: "no refresh token")}

      {:ok, %{refresh_token: refresh_token}} ->
        {:ok, refresh_token}

      {:error, error} ->
        {:error, error}
    end
  end

  defp exchange(refresh_token) do
    with {:ok, config} <- config() do
      config
      |> OAuth2.refresh_access_token(%{"refresh_token" => refresh_token})
      |> classify()
    end
  end

  defp classify({:error, %{response: %{body: %{"error" => reason}}}}) when reason in @refused,
    do: {:error, RefreshRefused.exception(reason: reason)}

  defp classify({:error, %{response: %{body: %{"error" => error} = body}}}) when is_binary(error),
    do: {:error, RefreshFailed.exception(error: error, description: body["error_description"])}

  defp classify({:error, %ServerUnreachableError{reason: reason}}),
    do: {:error, GitHubUnreachable.exception(reason: reason)}

  defp classify(answer), do: answer

  defp store(changeset, token, refresh_token, context) do
    changeset
    |> AshCloak.encrypt_and_set(:access_token, token["access_token"], context)
    |> Changeset.force_change_attribute(:access_token_expires_at, expires_at(token["expires_in"]))
    |> AshCloak.encrypt_and_set(:refresh_token, token["refresh_token"] || refresh_token, context)
  end

  defp expires_at(nil), do: nil

  defp expires_at(seconds) when is_binary(seconds), do: seconds |> String.to_integer() |> expires_at()

  defp expires_at(seconds) when is_integer(seconds), do: DateTime.shift(DateTime.utc_now(), second: seconds)

  defp config do
    strategy = AshAuthentication.Info.strategy!(User, :github)

    with {:ok, client_id} <- secret(strategy, :client_id),
         {:ok, client_secret} <- secret(strategy, :client_secret) do
      {:ok,
       [
         base_url: strategy.base_url,
         token_url: strategy.token_url,
         auth_method: strategy.auth_method,
         client_id: client_id,
         client_secret: client_secret,
         http_adapter: Application.fetch_env!(:ash_authentication, :http_adapter)
       ]}
    end
  end

  defp secret(%{name: name, resource: resource} = strategy, key) do
    {module, opts} = Map.fetch!(strategy, key)
    path = [:authentication, :strategies, name, key]

    case module.secret_for(path, resource, opts, %{}) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, MissingSecret.exception(path: path, resource: resource)}
    end
  end
end
