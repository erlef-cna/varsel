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

  alias Varsel.Accounts.User

  user_identity do
    user_resource User
  end

  postgres do
    table "user_identities"
    repo Varsel.Repo
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
      upsert_fields [:access_token, :access_token_expires_at, :refresh_token, :email]
      accept [:strategy]

      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      argument :user_id, :uuid, allow_nil?: false

      change AshAuthentication.UserIdentity.UpsertIdentityChange
      change Varsel.Accounts.UserIdentity.Changes.ApplyProviderEmail
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end
  end

  attributes do
    # The email this provider reported at the last sign-in, kept per identity
    # so a user can choose which of them is their primary address. It is a
    # provider-supplied fact and never proof of ownership: GitHub marks
    # addresses verified, hex.pm does not expose that at all, and hex only
    # returns an opt-in *public* address, so this is frequently nil.
    attribute :email, :string do
      public? true
      allow_nil? true
    end
  end
end
