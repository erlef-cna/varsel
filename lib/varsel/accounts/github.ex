# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.GitHub do
  @moduledoc """
  Thin client for checking that a GitHub account exists.

  Asks with the OAuth app's client credentials from `config :varsel, :github`
  when they are set: GitHub shows a profile's public email address to
  authenticated requests only, and grants them the authenticated rate limit.
  Without them the lookup confirms the login and never returns an address.
  Requests go through `Varsel.GitHub.Client`.
  """

  alias Varsel.GitHub.Client

  @typedoc """
  A GitHub account: its login as GitHub spells it, and the name and public
  email address on its profile, each `nil` when the profile shows none.
  """
  @type user :: %{login: String.t(), name: String.t() | nil, email: String.t() | nil}

  @doc "Whether a GitHub account with this login exists, with its canonical spelling, name and public address."
  @spec user(String.t()) :: {:ok, user()} | :not_found | {:error, term()}
  def user(login) when is_binary(login) do
    case Req.get(Client.api(auth()), url: "/users/:login", path_params: [login: login]) do
      {:ok, %Req.Response{status: 200, body: %{"login" => canonical} = body}} ->
        {:ok, %{login: canonical, name: blank_to_nil(body["name"]), email: body["email"]}}

      {:ok, %Req.Response{status: 404}} ->
        :not_found

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, {:http, status, body}}

      {:error, exception} ->
        {:error, exception}
    end
  end

  defp auth do
    config = Application.get_env(:varsel, :github, [])

    case {config[:client_id], config[:client_secret]} do
      {client_id, client_secret} when is_binary(client_id) and is_binary(client_secret) ->
        [auth: {:basic, "#{client_id}:#{client_secret}"}]

      _unset ->
        []
    end
  end

  defp blank_to_nil(name) when is_binary(name) do
    case String.trim(name) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp blank_to_nil(_name), do: nil
end
