# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Secrets do
  @moduledoc false
  use AshAuthentication.Secret

  alias Varsel.Accounts.User

  # OAuth strategies are declared at compile time and cannot be removed at
  # runtime, so an unconfigured provider is instead hidden from the sign-in
  # page (see `VarselWeb.AuthOverrides`) and fails closed here: a missing
  # secret makes the strategy return `MissingSecret` rather than half-run.
  @oauth_providers %{github: :github}

  @doc """
  Whether every secret backing `provider`'s strategy is configured.
  """
  @spec oauth_provider_configured?(atom()) :: boolean()
  def oauth_provider_configured?(provider) do
    case Map.fetch(@oauth_providers, provider) do
      {:ok, config_key} ->
        config = Application.get_env(:varsel, config_key, [])

        Enum.all?([:client_id, :client_secret, :redirect_uri], &Keyword.has_key?(config, &1))

      :error ->
        false
    end
  end

  @doc """
  Whether `strategy` should be offered on the sign-in page. Non-OAuth
  strategies (API keys, tokens) are not provider-gated and always pass.
  """
  @spec strategy_enabled?(struct()) :: boolean()
  def strategy_enabled?(%{name: name}) when is_map_key(@oauth_providers, name), do: oauth_provider_configured?(name)

  def strategy_enabled?(_strategy), do: true

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
