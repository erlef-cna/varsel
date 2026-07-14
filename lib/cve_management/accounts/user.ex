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
    notifiers: [Ash.Notifier.PubSub],
    extensions: [AshAuthentication, AshPaperTrail.Resource, AshGraphql.Resource]

  graphql do
    type :user
  end

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
        identity_resource CveManagement.Accounts.UserIdentity
      end

      api_key do
        api_key_relationship :valid_api_keys
      end
    end
  end

  postgres do
    table "users"
    repo CveManagement.Repo
  end

  paper_trail do
    change_tracking_mode :changes_only
    ignore_attributes [:inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, __MODULE__, domain: CveManagement.Accounts
  end

  actions do
    defaults [:read]

    read :get_by_subject do
      description "Get a user by the subject claim in a JWT"
      argument :subject, :string, allow_nil?: false
      get? true
      prepare AshAuthentication.Preparations.FilterBySubject
    end

    read :sign_in_with_api_key do
      argument :api_key, :string, allow_nil?: false, sensitive?: true
      prepare AshAuthentication.Strategy.ApiKey.SignInPreparation
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

      # The very first user to ever log in becomes a POC, so the CNA always
      # has someone who can manage roles. Only applies on insert (the upsert
      # leaves existing users' roles untouched).
      change fn changeset, _context ->
        Ash.Changeset.before_action(changeset, fn changeset ->
          if changeset.action_type == :create and Ash.count!(__MODULE__, authorize?: false) == 0 do
            Ash.Changeset.force_change_attribute(changeset, :role, :poc)
          else
            changeset
          end
        end)
      end
    end

    update :update do
      # Role is intentionally NOT accepted here: :update is self-editable
      # (see the policy below), and accepting role would let a non-POC
      # self-promote. Role changes go through :set_role, which is POC-only.
      accept [:name]
      primary? true
    end

    update :set_role do
      description "Sets a user's role. Restricted to POCs."
      accept [:role]
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

    policy action(:set_role) do
      authorize_if actor_attribute_equals(:role, :poc)
    end
  end

  pub_sub do
    module CveManagementWeb.Endpoint
    prefix "user"

    # A single stable topic ("user:all") that the user-management LiveView
    # subscribes to, so any change to any user (registration, role change)
    # re-runs its list query. Actor-scoped topics aren't needed: only POCs
    # can view the list, and the query itself re-applies authorization.
    publish_all :create, ["all"]
    publish_all :update, ["all"]
    publish_all :destroy, ["all"]
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

    attribute :role, CveManagement.Accounts.User.Role do
      public? true
      allow_nil? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    has_many :valid_api_keys, CveManagement.Accounts.ApiKey do
      filter expr(valid)
    end
  end

  identities do
    identity :unique_github_id, [:github_id]
  end
end
