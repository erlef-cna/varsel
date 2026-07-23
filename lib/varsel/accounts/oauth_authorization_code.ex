# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# Driven entirely by the OAuth2 server extension; no code interface is called.
defmodule Varsel.Accounts.OauthAuthorizationCode do
  @moduledoc false
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.Oauth2Server.AuthorizationCodeResource],
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "oauth_authorization_codes"
    repo Varsel.Repo
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      description "Issues an OAuth authorization code for a client/user grant."

      accept [
        :client_id,
        :user_id,
        :redirect_uri,
        :code_challenge,
        :scope,
        :resource_uri,
        :expires_at
      ]
    end

    update :consume do
      description "Marks an authorization code consumed; rejects a second use."
      accept []

      validate absent(:consumed_at) do
        message "code already used"
      end

      change atomic_update(:consumed_at, expr(now()))
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end
  end

  # Short-lived OAuth grant carrying its own expires_at/inserted_at semantics;
  # generic created/updated timestamps add no meaning.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
  attributes do
    uuid_v7_primary_key :id

    attribute :client_id, :uuid_v7 do
      allow_nil? false
      public? true
    end

    attribute :user_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :redirect_uri, :string do
      allow_nil? false
      public? true
    end

    attribute :code_challenge, :string do
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

    attribute :consumed_at, :utc_datetime_usec do
      public? true
    end
  end
end
