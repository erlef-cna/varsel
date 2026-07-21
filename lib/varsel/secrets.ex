# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Secrets do
  @moduledoc false
  use AshAuthentication.Secret

  alias Varsel.Accounts.User

  def secret_for([:authentication, :tokens, :signing_secret], User, _opts, _context) do
    Application.fetch_env(:varsel, :token_signing_secret)
  end

  def secret_for([:authentication, :strategies, :github, :client_id], User, _opts, _context) do
    get_github_config(:client_id)
  end

  def secret_for([:authentication, :strategies, :github, :redirect_uri], User, _opts, _context) do
    get_github_config(:redirect_uri)
  end

  def secret_for([:authentication, :strategies, :github, :client_secret], User, _opts, _context) do
    get_github_config(:client_secret)
  end

  def secret_for([:issuer_url], Varsel.Oauth2Server, _opts, _context) do
    Application.fetch_env(:varsel, :oauth2_issuer_url)
  end

  def secret_for([:resource_url], Varsel.Oauth2Server, _opts, _context) do
    Application.fetch_env(:varsel, :oauth2_resource_url)
  end

  def secret_for([:signing_secret], Varsel.Oauth2Server, _opts, _context) do
    Application.fetch_env(:varsel, :oauth2_signing_secret)
  end

  defp get_github_config(key) do
    :varsel
    |> Application.get_env(:github, [])
    |> Keyword.fetch(key)
  end
end
