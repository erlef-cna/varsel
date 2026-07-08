# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts.UserIdentity do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication.UserIdentity, AshPaperTrail.Resource]

  alias CveManagement.Accounts.User

  user_identity do
    user_resource User
  end

  postgres do
    table "user_identities"
    repo CveManagement.Repo
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
    belongs_to_actor :user, User, domain: CveManagement.Accounts
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
