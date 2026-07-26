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
  # Hex.pm is self-hostable, so its base URL is a required secret rather than
  # a constant baked into the strategy.
  @oauth_providers %{
    github: [:client_id, :client_secret, :redirect_uri],
    hex: [:client_id, :client_secret, :redirect_uri, :base_url]
  }

  @doc """
  Whether every secret backing `provider`'s strategy is configured.
  """
  @spec oauth_provider_configured?(atom()) :: boolean()
  def oauth_provider_configured?(provider) do
    case Map.fetch(@oauth_providers, provider) do
      {:ok, required_keys} ->
        # `|| []` rather than a get_env default: the key can be present and
        # explicitly nil, which no default covers.
        config = Application.get_env(:varsel, provider) || []

        Enum.all?(required_keys, &Keyword.has_key?(config, &1))

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

  # Serves every OAuth provider's secrets. Fetching (rather than defaulting)
  # keeps an unconfigured provider failing closed with `MissingSecret`.
  def secret_for([:authentication, :strategies, provider, key], User, _opts, _context)
      when is_map_key(@oauth_providers, provider) do
    :varsel
    |> Application.get_env(provider, [])
    |> Keyword.fetch(key)
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
end
