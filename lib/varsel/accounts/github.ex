# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.GitHub do
  @moduledoc """
  Thin client for checking that a GitHub account exists.

  Authenticates with the login app's client credentials from
  `config :varsel, :github` when they are set. GitHub shows a profile's
  public email address to authenticated requests only, so without them the
  lookup confirms the login and never returns an address. Request options
  (a `Req.Test` plug in tests) come from `config :varsel, :github_api`.
  """

  @typedoc """
  A GitHub account: its login as GitHub spells it, and the public email
  address on its profile, `nil` when the profile shows none.
  """
  @type user :: %{login: String.t(), email: String.t() | nil}

  @doc "Whether a GitHub account with this login exists, with its canonical spelling and public address."
  @spec user(String.t()) :: {:ok, user()} | :not_found
  def user(login) when is_binary(login) do
    case Req.get!(build_req(), url: "/users/#{URI.encode(login)}") do
      %Req.Response{status: 200, body: %{"login" => canonical} = body} ->
        {:ok, %{login: canonical, email: body["email"]}}

      %Req.Response{status: 404} ->
        :not_found
    end
  end

  defp build_req do
    Req.new(
      [
        base_url: "https://api.github.com",
        retry: false,
        headers: [{"accept", "application/vnd.github+json"}]
      ] ++ auth() ++ Application.get_env(:varsel, :github_api, [])
    )
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
end
