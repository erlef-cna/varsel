# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.ApiKey do
  @moduledoc """
  Personal access token for the JSON:API, GraphQL and MCP endpoints.

  Only a sha256 hash is persisted; the plaintext key exists solely in
  `__metadata__.plaintext_api_key` on the freshly created record and is
  shown to the user exactly once.
  """
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshPaperTrail.Resource]

  alias Varsel.Accounts.User

  postgres do
    table "api_keys"
    repo Varsel.Repo

    references do
      reference :user, on_delete: :delete
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    ignore_attributes [:api_key_hash, :inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    # Keys are hard-deleted on revoke, so versions can't reference the source row.
    reference_source? false
    belongs_to_actor :user, User, domain: Varsel.Accounts
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      description "Creates a personal API key for the acting user."
      accept [:name, :expires_at]

      change relate_actor(:user)

      change {AshAuthentication.Strategy.ApiKey.GenerateApiKey, prefix: :eefcna, hash: :api_key_hash}
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    # Users manage exactly their own keys.
    policy action_type(:read) do
      authorize_if relates_to_actor_via(:user)
    end

    policy action_type(:create) do
      authorize_if relating_to_actor(:user)
    end

    policy action_type(:destroy) do
      authorize_if relates_to_actor_via(:user)
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :name, :string do
      description "Human-readable label shown in the token settings UI."
      public? true
      allow_nil? false
    end

    attribute :api_key_hash, :binary do
      allow_nil? false
      sensitive? true
    end

    attribute :expires_at, :utc_datetime_usec do
      description "Optional expiry; nil means the key is valid until revoked."
      public? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :user, User do
      allow_nil? false
    end
  end

  calculations do
    calculate :valid, :boolean, expr(is_nil(expires_at) or expires_at > now())
  end

  identities do
    identity :unique_api_key, [:api_key_hash]
  end
end
