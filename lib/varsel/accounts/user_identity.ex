# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# All actions are AshAuthentication-managed and never called via a code interface.
defmodule Varsel.Accounts.UserIdentity do
  @moduledoc false
  # AshAuthentication-managed identity join between users and OAuth providers;
  # its schema is owned by the strategy and carries no user-meaningful timestamps.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
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
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end
  end
end
