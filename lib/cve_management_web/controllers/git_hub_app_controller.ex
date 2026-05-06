# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.GitHubAppController do
  @moduledoc """
  Handles the GitHub App OAuth flow for connecting a user's GitHub account
  to enable per-user advisory fetching (ADR-018).

  Routes:
  - GET /auth/github_app        — redirects to GitHub authorization
  - GET /auth/github_app/callback — exchanges code for tokens, stores them
  """
  use CveManagementWeb, :controller

  alias CveManagement.Accounts.GitHubAppToken
  alias CveManagement.GitHub.AppClient

  plug CveManagementWeb.Plugs.RequireAuthenticatedUser

  def authorize(conn, _params) do
    state = 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

    conn
    |> put_session(:github_app_oauth_state, state)
    |> redirect(external: AppClient.authorize_url(state))
  end

  def callback(conn, %{"code" => code, "state" => state} = _params) do
    current_user = conn.assigns.current_user

    with :ok <- verify_state(conn, state),
         {:ok, tokens} <- AppClient.exchange_code(code),
         {:ok, _token} <- store_token(current_user, tokens) do
      conn
      |> delete_session(:github_app_oauth_state)
      |> put_flash(:info, "GitHub App connected successfully.")
      |> redirect(to: ~p"/settings")
    else
      {:error, :invalid_state} ->
        conn
        |> put_flash(:error, "Invalid OAuth state. Please try again.")
        |> redirect(to: ~p"/settings")

      {:error, reason} ->
        require Logger

        Logger.error("GitHub App callback failed: #{inspect(reason)}")

        conn
        |> put_flash(:error, "GitHub App connection failed: #{inspect(reason)}")
        |> redirect(to: ~p"/settings")
    end
  end

  def callback(conn, _params) do
    conn
    |> put_flash(:error, "GitHub App authorization was denied or failed.")
    |> redirect(to: ~p"/settings")
  end

  defp verify_state(conn, state) do
    if get_session(conn, :github_app_oauth_state) == state do
      :ok
    else
      {:error, :invalid_state}
    end
  end

  defp store_token(user, %{access_token: access_token, refresh_token: refresh_token, expires_at: expires_at}) do
    GitHubAppToken
    |> Ash.Changeset.for_create(:upsert_from_oauth, %{
      user_id: user.id,
      access_token: access_token,
      refresh_token: refresh_token,
      expires_at: expires_at
    })
    |> Ash.create(actor: user)
  end
end
