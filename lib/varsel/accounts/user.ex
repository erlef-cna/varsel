# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User do
  @moduledoc false
  # Login is GitHub-OAuth-only (identity :unique_github_id on github_id); email
  # is secondary, GitHub-synced profile data and intentionally not an identity.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingIdentity
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    notifiers: [Ash.Notifier.PubSub],
    extensions: [AshAuthentication, AshPaperTrail.Resource, AshGraphql.Resource]

  alias AshAuthentication.Checks.AshAuthenticationInteraction
  alias AshOban.Checks.AshObanInteraction
  alias Varsel.Cases.Proposal

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
      token_resource Varsel.Accounts.Token
      signing_secret Varsel.Secrets
      store_all_tokens? true
      require_token_presence_for_authentication? true
    end

    strategies do
      github do
        client_id Varsel.Secrets
        redirect_uri Varsel.Secrets
        client_secret Varsel.Secrets
        identity_resource Varsel.Accounts.UserIdentity
      end

      api_key do
        api_key_relationship :valid_api_keys
      end
    end
  end

  field_policies do
    field_policy_bypass :*, AshAuthenticationInteraction do
      authorize_if always()
    end

    # The :notify_pocs Oban worker needs each POC's email; it reads through the
    # Oban bypass (see the read policy), so grant it every field too.
    field_policy_bypass :*, AshObanInteraction do
      authorize_if always()
    end

    # Whoever can read the row may see the display name.
    field_policy :name do
      authorize_if always()
    end

    # Everything else is POC-or-self only.
    field_policy [:email, :github_id, :github_handle, :role] do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(id == ^actor(:id))
    end
  end

  postgres do
    table "users"
    repo Varsel.Repo
  end

  paper_trail do
    change_tracking_mode :changes_only
    ignore_attributes [:inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, __MODULE__, domain: Varsel.Accounts
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
      description "Signs a user in by verifying a presented personal API key."
      argument :api_key, :string, allow_nil?: false, sensitive?: true
      prepare AshAuthentication.Strategy.ApiKey.SignInPreparation
    end

    create :register_with_github do
      description "Registers or updates a user from a GitHub OAuth sign-in."
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :unique_github_id
      upsert_fields [:github_handle, :name, :email]

      change AshAuthentication.GenerateTokenChange
      change AshAuthentication.Strategy.OAuth2.IdentityChange

      change Varsel.Accounts.User.Changes.ApplyOauthUserInfo
      change Varsel.Accounts.User.Changes.PromoteFirstUserToPoc
    end

    update :update do
      description "Updates a user's own editable profile fields (name)."
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
    bypass AshAuthenticationInteraction do
      authorize_if always()
    end

    # The :notify_pocs Oban worker lists every POC to email them; it has no
    # actor, so it authorizes through this bypass.
    bypass AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(id == ^actor(:id))
      # Users are also visible when loaded through a row the actor can read
      # (report reporter, proposal/comment authors, case workers/credits) —
      # the parent's own policy decided visibility, and the field policies
      # below restrict non-POC viewers to the display name.
      authorize_if accessing_from(Varsel.CVE.VulnerabilityReport, :reporter)
      authorize_if accessing_from(Proposal, :author)
      authorize_if accessing_from(Proposal, :resolved_by)
      authorize_if accessing_from(Varsel.Cases.Comment, :author)
      authorize_if accessing_from(Varsel.Cases.CaseAssignment, :user)
      authorize_if accessing_from(Varsel.Cases.CaseCredit, :user)
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
    module VarselWeb.Endpoint
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

    attribute :role, Varsel.Accounts.User.Role do
      public? true
      allow_nil? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    has_many :valid_api_keys, Varsel.Accounts.ApiKey do
      filter expr(valid)
    end
  end

  identities do
    identity :unique_github_id, [:github_id]
  end
end
