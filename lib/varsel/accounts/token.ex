# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# All actions are AshAuthentication-managed and never called via a code interface.
defmodule Varsel.Accounts.Token do
  @moduledoc false
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication.TokenResource, AshPaperTrail.Resource],
    simple_notifiers: [AshAuthentication.Phoenix.TokenRevocationNotifier]

  # Revoking a token only stops it authenticating *afresh*. A LiveView already
  # mounted keeps its actor until it remounts, so revocation also broadcasts a
  # disconnect to the socket that token opened.
  #
  # Sign-in names the socket from the JWT's claims (string keys) and revocation
  # from the token row (atom keys), so the template has to read both to arrive
  # at the same topic.
  token do
    endpoints [VarselWeb.Endpoint]
    live_socket_id_template &"users_sessions:#{&1["jti"] || &1[:jti]}"
  end

  postgres do
    table "tokens"
    repo Varsel.Repo
  end

  paper_trail do
    change_tracking_mode :changes_only
    ignore_attributes [:created_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    sensitive_attributes :redact
    # Expired tokens are hard-deleted by expunge_expired; the cleanup itself
    # is not an audit-worthy event
    reference_source? false
    create_version_on_destroy? false
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  # The three creates are AshAuthentication-managed token operations with no
  # canonical human-facing create; marking one primary? would misdirect default
  # create resolution.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingPrimaryAction
  actions do
    defaults [:read]

    read :expired do
      description "Look up all expired tokens."
      filter expr(expires_at < now())
    end

    # Revoking flips `purpose` on the row itself, so there is no separate
    # revocation row to exclude here.
    read :list_sessions do
      description "The unexpired sign-in sessions belonging to a subject."
      argument :subject, :string, allow_nil?: false, sensitive?: true

      filter expr(subject == ^arg(:subject) and purpose == "user" and expires_at > now())
      prepare build(sort: [created_at: :desc])
    end

    read :get_token do
      description "Look up a token by JTI or token, and an optional purpose."
      get? true
      argument :token, :string, sensitive?: true
      argument :jti, :string, sensitive?: true
      argument :purpose, :string, sensitive?: false

      prepare AshAuthentication.TokenResource.GetTokenPreparation
    end

    action :revoked?, :boolean do
      description "Returns true if a revocation token is found for the provided token"
      argument :token, :string, sensitive?: true
      argument :jti, :string, sensitive?: true

      run AshAuthentication.TokenResource.IsRevoked
    end

    create :revoke_token do
      description "Revoke a token. Creates a revocation token corresponding to the provided token."
      accept [:extra_data]
      argument :token, :string, allow_nil?: false, sensitive?: true

      change AshAuthentication.TokenResource.RevokeTokenChange
    end

    create :revoke_jti do
      description "Revoke a token by JTI. Creates a revocation token corresponding to the provided jti."
      accept [:extra_data]
      argument :subject, :string, allow_nil?: false, sensitive?: true
      argument :jti, :string, allow_nil?: false, sensitive?: true

      change AshAuthentication.TokenResource.RevokeJtiChange
    end

    create :store_token do
      description "Stores a token used for the provided purpose."
      accept [:extra_data, :purpose]
      argument :token, :string, allow_nil?: false, sensitive?: true
      change AshAuthentication.TokenResource.StoreTokenChange
      change Varsel.Accounts.Token.Changes.RecordSignInDetails
    end

    destroy :expunge_expired do
      description "Deletes expired tokens."
      change filter(expr(expires_at < now()))
    end

    update :revoke_all_stored_for_subject do
      description "Revokes all stored tokens for a specific subject."
      accept [:extra_data]
      argument :subject, :string, allow_nil?: false, sensitive?: true
      change AshAuthentication.TokenResource.RevokeAllStoredForSubjectChange
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      description "AshAuthentication can interact with the token resource"
      authorize_if always()
    end

    # Your own sessions, and nobody else's — not even a POC's.
    policy action(:list_sessions) do
      description "A user may list their own sessions"
      access_type :strict
      authorize_if expr(^arg(:subject) == "user?id=" <> ^actor(:id))
    end
  end

  attributes do
    attribute :jti, :string do
      primary_key? true
      public? true
      allow_nil? false
      sensitive? true
    end

    attribute :subject, :string do
      allow_nil? false
      public? true
    end

    attribute :expires_at, :utc_datetime do
      allow_nil? false
      public? true
    end

    attribute :purpose, :string do
      allow_nil? false
      public? true
    end

    attribute :extra_data, :map do
      public? true
    end

    create_timestamp :created_at
    update_timestamp :updated_at
  end
end
