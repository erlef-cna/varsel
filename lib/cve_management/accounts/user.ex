# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts.User do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication]

  authentication do
    add_ons do
      log_out_everywhere do
        apply_on_password_change? true
      end
    end

    tokens do
      enabled? true
      token_resource CveManagement.Accounts.Token
      signing_secret CveManagement.Secrets
      store_all_tokens? true
      require_token_presence_for_authentication? true
    end

    strategies do
      github do
        client_id CveManagement.Secrets
        redirect_uri CveManagement.Secrets
        client_secret CveManagement.Secrets
      end
    end
  end

  postgres do
    table "users"
    repo CveManagement.Repo
  end

  actions do
    defaults [:read]

    read :get_by_subject do
      description "Get a user by the subject claim in a JWT"
      argument :subject, :string, allow_nil?: false
      get? true
      prepare AshAuthentication.Preparations.FilterBySubject
    end

    create :register_with_github do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :unique_github_id
      upsert_fields [:github_handle, :name, :email]

      change AshAuthentication.GenerateTokenChange
      change AshAuthentication.Strategy.OAuth2.IdentityChange

      change fn changeset, _ ->
        user_info = Ash.Changeset.get_argument(changeset, :user_info)

        changeset
        |> Ash.Changeset.force_change_attribute(:github_id, to_string(user_info["sub"]))
        |> Ash.Changeset.force_change_attribute(:github_handle, user_info["preferred_username"])
        |> Ash.Changeset.force_change_attribute(:name, user_info["name"])
        |> Ash.Changeset.force_change_attribute(:email, user_info["email"])
      end
    end

    update :update do
      accept [:name, :role, :public_gpg_key]
      primary? true
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(id == ^actor(:id))
    end

    policy action(:update) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(id == ^actor(:id))
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :email, :string do
      public? true
      allow_nil? true
    end

    attribute :github_id, :string do
      public? true
      allow_nil? true
    end

    attribute :github_handle, :string do
      public? true
      allow_nil? true
    end

    attribute :name, :string do
      public? true
      allow_nil? true
    end

    attribute :role, :atom do
      public? true
      constraints one_of: [:poc, :supporter]
      allow_nil? true
    end

    attribute :public_gpg_key, :string do
      public? true
      allow_nil? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  identities do
    identity :unique_github_id, [:github_id]
  end
end
