# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.SignInTest do
  # Not async: these mutate the application-wide provider configuration.
  use VarselWeb.ConnCase, async: false

  alias AshAuthentication.Info

  setup do
    original = Application.get_env(:varsel, :github)
    on_exit(fn -> Application.put_env(:varsel, :github, original) end)
  end

  defp put_github(config), do: Application.put_env(:varsel, :github, config)

  defp visible_strategies do
    Varsel.Accounts.User
    |> Info.authentication_strategies()
    |> Enum.filter(&Varsel.Secrets.strategy_enabled?/1)
    |> Enum.map(& &1.name)
  end

  describe "oauth_provider_configured?/1" do
    test "is false when the provider has no configuration" do
      put_github([])

      refute Varsel.Secrets.oauth_provider_configured?(:github)
    end

    test "is false when the configuration is missing a secret" do
      put_github(client_id: "id", redirect_uri: "https://example.com/callback")

      refute Varsel.Secrets.oauth_provider_configured?(:github)
    end

    test "is true once every secret is present" do
      put_github(
        client_id: "id",
        client_secret: "secret",
        redirect_uri: "https://example.com/callback"
      )

      assert Varsel.Secrets.oauth_provider_configured?(:github)
    end

    test "is false for a provider that is not OAuth-gated" do
      refute Varsel.Secrets.oauth_provider_configured?(:api_key)
    end
  end

  describe "strategy_enabled?/1" do
    test "hides an unconfigured OAuth provider" do
      put_github([])

      refute :github in visible_strategies()
    end

    test "shows a configured OAuth provider" do
      put_github(
        client_id: "id",
        client_secret: "secret",
        redirect_uri: "https://example.com/callback"
      )

      assert :github in visible_strategies()
    end

    test "leaves non-OAuth strategies alone" do
      put_github([])

      assert :api_key in visible_strategies()
    end
  end

  describe "the sign-in page" do
    test "offers no GitHub link when GitHub is unconfigured", %{conn: conn} do
      put_github([])

      refute conn |> get(~p"/sign-in") |> html_response(200) =~ "/auth/user/github"
    end

    test "offers a GitHub link once GitHub is configured", %{conn: conn} do
      put_github(
        client_id: "id",
        client_secret: "secret",
        redirect_uri: "https://example.com/callback"
      )

      assert conn |> get(~p"/sign-in") |> html_response(200) =~ "/auth/user/github"
    end
  end
end
