# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Assent.Hex do
  @moduledoc """
  Hex.pm OAuth2 strategy.

  Hex.pm runs a plain OAuth2 server, *not* an OpenID Connect provider: there is
  no discovery document and no userinfo endpoint, so the profile is read from
  `GET /api/users/me` and normalized here.

  Two consequences shape the mapping below:

    * There is no `openid`/`profile`/`email` scope. `api:read` is the narrowest
      scope that can read the user endpoint, so signing in necessarily asks for
      registry read access.

    * `/api/users/me` exposes no numeric or UUID id — only `username`, which
      hex.pm never lets a user change (it is cast when the account is built and
      in no update path), so it is the stable subject.

  The email is the user's *public* email, which is opt-in on hex.pm and
  therefore frequently absent. Hex.pm never exposes whether an address is
  verified, so `email_verified` is always false and the strategy must not use
  it to attach a sign-in to a pre-existing account.
  """

  use Assent.Strategy.OAuth2.Base

  @impl Assent.Strategy.OAuth2.Base
  def default_config(_config) do
    [
      authorize_url: "/oauth/authorize",
      token_url: "/api/oauth/token",
      user_url: "/api/users/me",
      authorization_params: [scope: "api:read"],
      auth_method: :client_secret_post,
      # Hex.pm requires PKCE for the authorization_code grant; a token request
      # without a code_verifier is rejected outright.
      code_verifier: true
    ]
  end

  @impl Assent.Strategy.OAuth2.Base
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["username"],
       "preferred_username" => user["username"],
       "name" => user["full_name"],
       "email" => user["email"],
       # Hex.pm has a `verified` column on emails but never renders it, so
       # ownership of this address is unproven as far as we are concerned.
       "email_verified" => false
     }}
  end
end
