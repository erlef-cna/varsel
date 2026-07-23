# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# Driven entirely by the OAuth2 server extension; no code interface is called.
defmodule Varsel.Accounts.OauthRefreshToken do
  @moduledoc false
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.Oauth2Server.RefreshTokenResource],
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "oauth_refresh_tokens"
    repo Varsel.Repo
  end

  actions do
    defaults [:read, :destroy]

    create :issue do
      primary? true
      description "Issues a refresh token as the head of a new rotation chain."

      accept [
        :id,
        :chain_id,
        :generation,
        :token_hash,
        :client_id,
        :user_id,
        :scope,
        :resource_uri,
        :expires_at
      ]
    end

    update :rotate do
      description "Rotates a refresh token, linking it to its successor in the chain."
      argument :rotated_to_id, :uuid_v7, allow_nil?: false
      accept []

      change AshAuthentication.Oauth2Server.Changes.RotateRefreshToken
    end

    update :revoke do
      description "Revokes a refresh token."
      primary? true
      accept []
      change atomic_update(:revoked_at, expr(now()))
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end
  end

  # Token carries its own explicit expires_at/revoked_at lifecycle; generic
  # created/updated timestamps add no meaning.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
  attributes do
    attribute :token_hash, :string do
      allow_nil? false
      public? true
    end

    attribute :client_id, :uuid_v7 do
      allow_nil? false
      public? true
    end

    attribute :user_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :scope, :string do
      allow_nil? false
      public? true
    end

    attribute :resource_uri, :string do
      allow_nil? false
      public? true
    end

    attribute :expires_at, :utc_datetime_usec do
      allow_nil? false
      public? true
    end

    attribute :chain_id, :uuid_v7 do
      allow_nil? false
      public? true
    end

    attribute :rotated_to_id, :uuid_v7 do
      public? true
    end

    attribute :rotated_at, :utc_datetime_usec do
      public? true
    end

    attribute :revoked_at, :utc_datetime_usec do
      public? true
    end

    attribute :id, :uuid_v7 do
      primary_key? true
      allow_nil? false
      default &Ash.UUIDv7.generate/0
      writable? true
      public? true
    end

    attribute :generation, :integer do
      allow_nil? false
      default 0
      public? true
    end
  end

  identities do
    identity :by_token_hash, [:token_hash]
  end
end
