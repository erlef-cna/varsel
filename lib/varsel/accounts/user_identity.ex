# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# All actions are AshAuthentication-managed and never called via a code interface.
#
# credo:disable-for-this-file AshCredo.Check.Design.MissingTimestamps
# The schema is owned by the strategy and carries no user-meaningful timestamps.
#
# credo:disable-for-this-file AshCredo.Check.Design.MissingIdentity
# `email` is deliberately non-unique: one address may be reported by several of
# a user's providers, and unrelated accounts may share one. Uniqueness belongs
# on the account's chosen primary email instead (`Varsel.Accounts.User`).
defmodule Varsel.Accounts.UserIdentity do
  @moduledoc false
  # AshAuthentication-managed identity join between users and OAuth providers.
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication.UserIdentity, AshPaperTrail.Resource]

  alias Ash.Type.CiString
  alias Varsel.Accounts.User
  alias Varsel.Accounts.UserIdentity.Changes.ReconcileUserNotificationEmail

  user_identity do
    user_resource User
  end

  postgres do
    table "user_identities"
    repo Varsel.Repo

    references do
      # A provider link is meaningless without the account it links to.
      reference :user, on_delete: :delete
    end

    custom_statements do
      # One address belongs to one account. Not a unique index on `email`:
      # a single user legitimately holds the same address on several providers
      # (GitHub and Hex.pm both reporting it), which a unique index would
      # refuse. The exclusion constraint refuses only the case that matters —
      # the same address under a *different* user — and does it in the
      # database, where two concurrent OAuth callbacks cannot race past it.
      # `lower(email::text)` rather than the citext column itself: gist has no
      # operator class for citext, and casting alone would compare case
      # *sensitively* — letting Alice@x.com and alice@x.com land on separate
      # accounts, which is exactly what this is here to stop.
      statement :user_identities_one_account_per_email do
        up """
        ALTER TABLE user_identities
        ADD CONSTRAINT user_identities_one_account_per_email
        EXCLUDE USING gist ((lower(email::text)) WITH =, user_id WITH <>)
        WHERE (email IS NOT NULL)
        """

        down """
        ALTER TABLE user_identities
        DROP CONSTRAINT user_identities_one_account_per_email
        """
      end
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    # OAuth tokens (and their expiry, which changes on every login) are
    # deliberately not versioned
    ignore_attributes [:access_token, :access_token_expires_at, :refresh_token]
    only_when_changed? true
    store_action_name? true
    # Identities are hard-deleted when a user disconnects a provider
    reference_source? false
    belongs_to_actor :user, User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    # Mirrors the action AshAuthentication would generate (see
    # `AshAuthentication.UserIdentity.Transformer`), with the provider's email
    # recorded alongside the tokens so each linked provider keeps the address
    # it reported. Redefining it here means the transformer validates this
    # action rather than building its own.
    create :upsert do
      description "Creates or refreshes the identity row for an OAuth sign-in."
      upsert? true
      upsert_identity :unique_on_strategy_and_uid
      upsert_fields [:access_token, :access_token_expires_at, :refresh_token, :email, :username]
      accept [:strategy]

      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      argument :user_id, :uuid, allow_nil?: false

      change AshAuthentication.UserIdentity.UpsertIdentityChange
      change Varsel.Accounts.UserIdentity.Changes.ApplyProviderFields
      change ReconcileUserNotificationEmail
    end

    destroy :destroy do
      description "Unlinks a provider from the account it is linked to."
      primary? true
      # The reconcile runs in an after_action hook, inside the transaction.
      require_atomic? false

      change ReconcileUserNotificationEmail
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    # Identities are only ever read through the user they belong to, whose own
    # policy already decided whether that row is visible. The OAuth tokens stay
    # private attributes, so they are never readable through the API at all.
    policy action_type(:read) do
      authorize_if accessing_from(User, :identities)
    end

    # Your own providers, and nobody else's — a POC has no more business
    # removing someone's way in than picking their address. And never the last
    # one: providers are the only way to sign in, so unlinking it would lock
    # the account out permanently, with no password to fall back on and no
    # session left to attach a replacement from.
    policy action_type(:destroy) do
      forbid_if expr(users_only_strategy?)
      authorize_if expr(user_id == ^actor(:id))
    end
  end

  attributes do
    # The email this provider reported at the last sign-in, kept per identity
    # so a user can choose which of them is their primary address. It is a
    # provider-supplied fact and never proof of ownership: GitHub marks
    # addresses verified, hex.pm does not expose that at all, and hex only
    # returns an opt-in *public* address, so this is frequently nil.
    # Case-insensitive: nobody has two accounts by capitalising an address
    # differently, and the constraint above has to see those as one. The
    # original casing is kept so the address is shown back as it was given.
    attribute :email, CiString do
      public? false
      allow_nil? true
    end

    # The username this provider reported at the last sign-in, kept per
    # identity. Case-insensitive for the same reason: both providers treat
    # handles that way, and hexpm lowercases them outright.
    attribute :username, CiString do
      public? false
      allow_nil? true
    end
  end

  calculations do
    calculate :users_only_strategy?, :boolean, expr(user_identity_count < 2) do
      public? true
    end
  end

  aggregates do
    count :user_identity_count, __MODULE__ do
      filter expr(user_id == parent(user_id))
      authorize? false
    end
  end
end
