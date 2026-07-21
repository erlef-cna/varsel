# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Oauth2Server do
  @moduledoc """
  OAuth 2.1 authorization-server configuration.

  See `AshAuthentication.Oauth2Server` for all options.
  """

  use AshAuthentication.Oauth2Server,
    otp_app: :varsel,
    user_resource: Varsel.Accounts.User,
    issuer_url: {Varsel.Secrets, []},
    resource_url: {Varsel.Secrets, []},
    signing_secret: {Varsel.Secrets, []},
    client_resource: Varsel.Accounts.OauthClient,
    authorization_code_resource: Varsel.Accounts.OauthAuthorizationCode,
    refresh_token_resource: Varsel.Accounts.OauthRefreshToken,
    consent_resource: Varsel.Accounts.OauthConsent,
    scopes: ["mcp", "gql"],
    # Dynamic client registration (RFC 7591). The library default is
    # `false` for safety; the installer turns it on because most
    # people setting up an OAuth server today need it for MCP-style
    # flows (ChatGPT Apps SDK, Claude.ai connectors, etc.). Set to
    # `false` if your auth server is for a fixed set of first-party
    # clients only.
    dcr_enabled?: true,
    sign_in_path: "/sign-in"
end
