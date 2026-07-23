# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# Driven entirely by the OAuth2 server extension; no code interface is called.
defmodule Varsel.Accounts.OauthConsent do
  @moduledoc false
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "oauth_consents"
    repo Varsel.Repo
  end

  actions do
    defaults [:read, :destroy]

    create :grant do
      primary? true
      description "Records (or refreshes) a user's consent for an OAuth client and scope."
      upsert? true
      upsert_identity :by_user_client
      accept [:user_id, :client_id, :scope]
      change set_attribute(:granted_at, &DateTime.utc_now/0)
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end
  end

  # Consent record carries its own explicit granted_at; generic
  # created/updated timestamps add no meaning.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
  attributes do
    uuid_v7_primary_key :id

    attribute :user_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :client_id, :uuid_v7 do
      allow_nil? false
      public? true
    end

    attribute :scope, :string do
      allow_nil? false
      public? true
    end

    attribute :granted_at, :utc_datetime_usec do
      allow_nil? false
      public? true
    end
  end

  identities do
    identity :by_user_client, [:user_id, :client_id]
  end
end
