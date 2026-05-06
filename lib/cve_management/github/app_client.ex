# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.GitHub.AppClient do
  @moduledoc """
  Low-level HTTP helpers for the GitHub App OAuth token endpoints.
  """

  @authorize_url "https://github.com/login/oauth/authorize"
  @token_url "https://github.com/login/oauth/access_token"
  @req_opts Keyword.take(Application.compile_env(:cve_management, :github_app, []), [:plug])

  @doc """
  Returns the query string params for the GitHub App authorization redirect.
  """
  def authorize_params(state) do
    config = github_app_config()

    URI.encode_query(%{
      client_id: config[:client_id],
      redirect_uri: config[:redirect_uri],
      scope: "security_events notifications",
      state: state
    })
  end

  @doc """
  Returns the full GitHub App authorization URL with encoded params.
  """
  def authorize_url(state) do
    "#{@authorize_url}?#{authorize_params(state)}"
  end

  @doc """
  Exchanges an authorization code for an access + refresh token pair.
  Returns `{:ok, token_map}` or `{:error, reason}`.
  """
  def exchange_code(code) do
    config = github_app_config()

    post_token(
      grant_type: "authorization_code",
      code: code,
      client_id: config[:client_id],
      client_secret: config[:client_secret],
      redirect_uri: config[:redirect_uri]
    )
  end

  @doc """
  Refreshes an expired access token using the refresh token.
  Returns `{:ok, token_map}` or `{:error, reason}`.
  """
  def refresh_token(refresh_token) do
    config = github_app_config()

    post_token(
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: config[:client_id],
      client_secret: config[:client_secret]
    )
  end

  defp post_token(params) do
    response =
      Req.post!(
        @token_url,
        [form: params, headers: [accept: "application/json"]] ++ @req_opts
      )

    case response.body do
      %{
        "access_token" => access_token,
        "refresh_token" => refresh_token,
        "expires_in" => expires_in
      } ->
        expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)
        {:ok, %{access_token: access_token, refresh_token: refresh_token, expires_at: expires_at}}

      %{"error" => error} ->
        {:error, error}

      _ ->
        {:error, :unexpected_response}
    end
  end

  defp github_app_config do
    Application.get_env(:cve_management, :github_app, [])
  end
end
