# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User do
  @moduledoc false

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    notifiers: [Ash.Notifier.PubSub],
    extensions: [
      AshAuthentication,
      Varsel.Accounts.Strategy.Github,
      Varsel.Accounts.Strategy.Hex,
      AshPaperTrail.Resource,
      AshGraphql.Resource,
      AshAdmin.Resource
    ]

  alias AshAuthentication.Checks.AshAuthenticationInteraction
  alias AshOban.Checks.AshObanInteraction
  alias Varsel.Accounts.User.Changes.ApplyProviderProfile
  alias Varsel.Accounts.User.Changes.PromoteFirstUserToPoc
  alias Varsel.Accounts.User.Changes.ResolveOauthIdentity
  alias Varsel.Accounts.UserIdentity
  alias Varsel.Cases.Proposal

  # Gates the mock (GitHub-bypassing) sign-in action at compile time. Its
  # changes live under `dev/`, which is only compiled for :dev and :test, so
  # this must match — `Mix.env/0` is read while compiling, never at runtime
  # (Mix is not available in a release).
  @mock_login? Mix.env() in [:dev, :test]

  admin do
    actor? true
  end

  graphql do
    type :user
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

    # Whoever can read the row may see the display name, and whether the
    # account still exists in its own right or has been merged away.
    field_policy [
      :name,
      :github_username,
      :hex_username,
      :display_name,
      :avatar_url
    ] do
      authorize_if always()
    end

    # Everything else is POC-or-self only.
    field_policy [:notification_email, :identity_emails, :role] do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(id == ^actor(:id))
    end
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
      varsel_github do
        client_id Varsel.Secrets
        redirect_uri Varsel.Secrets
        client_secret Varsel.Secrets
        identity_resource UserIdentity
        # A provider is linked to an account from an authenticated session,
        # never by presenting a matching email — not even a verified one, which
        # the strategy would otherwise trust by default. Reaching an existing
        # account this way requires only control of an address, so possession
        # of the account itself has to be proven instead.
        trust_email_verified? false
        on_untrusted_email_match :reject
      end

      # Hex.pm is plain OAuth2 rather than OIDC, so its endpoints and profile
      # mapping live in `Varsel.Accounts.Strategy.Hex`, which also refuses to
      # match a sign-in to an existing account by email — hex.pm never asserts
      # that an address is verified. `base_url` is configured because hex.pm
      # is self-hostable.
      hex do
        client_id Varsel.Secrets
        redirect_uri Varsel.Secrets
        client_secret Varsel.Secrets
        base_url Varsel.Secrets
        identity_resource UserIdentity
      end

      api_key do
        api_key_relationship :valid_api_keys
      end
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
    # Accounts are really deleted, so a version cannot point at its source row.
    # The id stays on the version either way, which is what the trail needs.
    reference_source? false
    belongs_to_actor :user, __MODULE__, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    read :read do
      primary? true
      description "Lists users."

      pagination offset?: true,
                 keyset?: true,
                 countable: :by_default,
                 default_limit: 25,
                 required?: false
    end

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
      # GitHub OAuth is the only way a real user comes into being, so it stays
      # the primary create even in dev builds, where :mock_sign_in adds a
      # second one.
      primary? true
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      # Which account a sign-in belongs to is settled by the provider's iss/sub
      # on the identity row; this only resolves a pre-existing local account,
      # and never links on its own (see `trust_email_verified? false`).
      upsert_identity :unique_notification_email
      # Not :notification_email — that address is the user's choice (see
      # :set_notification_email) and a later sign-in must not re-point it.
      upsert_fields [:name]

      change AshAuthentication.GenerateTokenChange
      change ApplyProviderProfile
      change PromoteFirstUserToPoc

      # Last: mid-link it points the upsert at the account being linked to, and
      # must not be undone by a change that seeds from what the provider said.
      change ResolveOauthIdentity
    end

    create :register_with_hex do
      description "Registers or updates a user from a Hex.pm OAuth sign-in."
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      # As above: matching an address never *links* on its own. Hex.pm asserts
      # no verified email, so `on_untrusted_email_match :reject` refuses the
      # sign-in and the user links hex from an authenticated session instead.
      upsert_identity :unique_notification_email
      upsert_fields [:name]

      change AshAuthentication.GenerateTokenChange
      change ApplyProviderProfile
      change PromoteFirstUserToPoc

      # Last: mid-link it points the upsert at the account being linked to, and
      # must not be undone by a change that seeds from what the provider said.
      change ResolveOauthIdentity
    end

    update :set_notification_email do
      description "Sets the account's notification email to one a linked provider reported."
      accept [:notification_email]
      # Checking the address against the linked identities needs to read them.
      require_atomic? false

      change Varsel.Accounts.User.Changes.ValidateNotificationEmailIsLinked
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

    destroy :destroy do
      description "Deletes an account, keeping what it wrote."
      primary? true
      # Revoking the tokens reads them first.
      require_atomic? false

      # What the account *was* — its providers, API keys, and the case
      # assignments only it could act on — goes with it, by cascade. What it
      # *wrote* stays and loses its author: comments, proposals, reports and
      # credits nilify, because a discussion does not stop being a discussion
      # when one participant leaves. Paper-trail versions keep the raw id (the
      # foreign key is dropped), so the audit trail can still say which account
      # made a change after the account is gone.
      #
      # Tokens are the exception to the cascade: they are keyed by subject
      # rather than by a foreign key, so nothing removes them on their own.
      change Varsel.Accounts.User.Changes.RevokeTokens
    end

    if @mock_login? do
      create :mock_sign_in do
        description "Dev-only: upserts a dummy user for the given role and signs it in."
        accept [:role]
        upsert? true
        upsert_identity :unique_notification_email

        # Re-signing in as the same role must reuse the same row, so the
        # synthetic address is derived from the role rather than random.
        change Varsel.Accounts.User.Changes.ApplyMockProfile
        change Varsel.Accounts.User.Changes.MockGenerateToken

        metadata :token, :string do
          allow_nil? false
        end
      end
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

    if @mock_login? do
      # The mock sign-in is the caller's way of *becoming* an actor, so there is
      # none to authorize against. It only exists in dev builds.

      # Bypass so that the access check below does not trigger
      bypass action(:mock_sign_in) do
        access_type :strict
        authorize_if actor_absent()
      end

      # Normal so that it is checked eagerly
      policy action(:mock_sign_in) do
        access_type :strict
        authorize_if actor_absent()
      end
    end

    # Nothing about a user is public. Authentication, Oban and mock-login are
    # the bypasses above, so every other path needs someone to be asking; the
    # read policy below then narrows to what that someone may see.
    policy always() do
      access_type :strict
      authorize_if actor_present()
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

    # Nobody picks anyone else's address, POCs included: the choice is between
    # the addresses that user's own providers reported, and it decides where
    # their mail goes.
    policy action(:set_notification_email) do
      authorize_if expr(id == ^actor(:id))
    end

    # Your own account, or a POC removing someone from the team — the same
    # reach `:set_role` already grants, including over other POCs.
    policy action_type(:destroy) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(id == ^actor(:id))
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

    # Seeded from the first provider to report one and thereafter chosen by the
    # user from their linked identities' emails (see :set_notification_email), so it
    # is never silently re-pointed by a later sign-in. Nil for accounts whose
    # providers reported no address.
    # Case-insensitive so the unique identity below actually holds: otherwise
    # two accounts could claim the same address by capitalising it
    # differently, and neither this nor the check against the addresses a
    # user's providers reported would notice.
    attribute :notification_email, Ash.Type.CiString do
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

    # The linked OAuth providers. Their emails are the candidates a user may
    # choose their primary email from.
    has_many :identities, UserIdentity do
      public? false
      destination_attribute :user_id
    end
  end

  calculations do
    # The name a user is shown under, and the order the console lists them in.
    # Both live in the query rather than the LiveView so a page of users is
    # sorted against the whole table, not just the rows already loaded.
    calculate :display_name,
              :string,
              expr(coalesce([name, hex_username, github_username, "user"])) do
      public? true
    end

    calculate :poc_first, :integer, expr(if role == :poc, do: 0, else: 1)

    calculate :hex_username,
              :string,
              expr(min(identities, field: :username, filter: expr(strategy == "hex"))) do
      public? true
    end

    calculate :github_username,
              :string,
              expr(min(identities, field: :username, filter: expr(strategy == "github"))) do
      public? true
    end

    calculate :identity_emails, {:array, :string}, expr(list(identities, field: :email)) do
      public? true
    end

    # GitHub serves an avatar straight off the profile URL, so a linked GitHub
    # account is the best picture we have. Otherwise fall back to Gravatar,
    # keyed on the notification address — which is what hex.pm itself does, and
    # hex publishes no avatar of its own. `d=mp` yields a neutral silhouette
    # rather than a 404 when the address has no Gravatar, so the <img> always
    # resolves.
    calculate :avatar_url,
              :string,
              expr(
                coalesce([
                  "https://github.com/" <> github_username <> ".png",
                  "https://www.gravatar.com/avatar/" <>
                    md5(string_downcase(string_trim(notification_email))) <> "?d=mp"
                ])
              ) do
      public? true
    end
  end

  identities do
    # Resolves an OAuth sign-in to an existing local account. Postgres allows
    # many NULLs in a unique index, so accounts whose providers reported no
    # address (common on hex.pm, where it is opt-in) do not collide.
    identity :unique_notification_email, [:notification_email]
  end
end
