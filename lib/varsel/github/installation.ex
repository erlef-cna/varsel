# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation do
  @moduledoc """
  An installation of the GitHub App, as GitHub last listed it, and the
  installation token last minted for it.

  The `:sync_all` schedule keeps the rows in step with GitHub. An account
  the App is not installed on has no row. An installation with
  `repository_selection: :all` covers every repository of its account. An
  installation with `:selected` covers the repositories in
  `Varsel.GitHub.InstallationRepository`.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.GitHub,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshOban, AshCloak]

  alias AshOban.Checks.AshObanInteraction
  alias Varsel.GitHub.Installation.Actions.PublicReadToken
  alias Varsel.GitHub.Installation.Actions.SyncAll
  alias Varsel.GitHub.Installation.Actions.Token
  alias Varsel.GitHub.Installation.Kind
  alias Varsel.GitHub.Installation.RepositorySelection
  alias Varsel.GitHub.InstallationRepository
  alias Varsel.GitHub.UserInstallation
  alias Varsel.Types.OkResult

  postgres do
    table "github_installations"
    repo Varsel.Repo
  end

  field_policies do
    field_policy [:token, :token_expires_at] do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if actor_attribute_equals(:system, :github_public_read)
      authorize_if AshObanInteraction
    end

    field_policy :* do
      authorize_if always()
    end
  end

  oban do
    scheduled_actions do
      schedule :sync_all, "*/15 * * * *",
        action: :sync_all,
        worker_module_name: Varsel.GitHub.Installation.SyncAllWorker,
        queue: :github_sync,
        max_attempts: 3
    end
  end

  cloak do
    vault Varsel.Vault
    attributes [:token]
  end

  actions do
    read :read do
      description "Lists the installations of the GitHub App."
      primary? true
      public? false
    end

    read :for_repository do
      description """
      Returns the installation of the GitHub App that covers the repository
      `owner/repo`, or nil. A suspended installation covers nothing.
      """

      public? false
      get? true

      argument :owner, :ci_string do
        allow_nil? false
        constraints match: ~r/\A[^\/]+\z/
      end

      argument :repo, :ci_string do
        allow_nil? false
        constraints match: ~r/\A[^\/]+\z/
      end

      filter expr(
               account == ^arg(:owner) and is_nil(suspended_at) and
                 (repository_selection == :all or
                    exists(repositories, owner == ^arg(:owner) and repo == ^arg(:repo)))
             )
    end

    read :for_account do
      description """
      Returns the installation of the GitHub App on the account `account`, or
      nil. A suspended installation is nil.
      """

      public? false
      get? true

      argument :account, :ci_string do
        allow_nil? false
        constraints match: ~r/\A[^\/]+\z/
      end

      filter expr(account == ^arg(:account) and is_nil(suspended_at))
    end

    create :sync do
      description "Stores an installation as GitHub lists it."
      public? false
      accept [:id, :account, :kind, :repository_selection, :suspended_at]
      upsert? true
      upsert_fields [:account, :kind, :repository_selection, :suspended_at, :synced_at]

      change set_attribute(:synced_at, &DateTime.utc_now/0)
    end

    destroy :forget do
      description "Removes an installation that GitHub no longer lists."
      primary? true
      public? false
    end

    update :store_token do
      description "Stores a newly minted installation token."
      public? false
      accept [:token, :token_expires_at]
    end

    action :sync_all, OkResult do
      description """
      Makes the installations and their selected repositories match what
      GitHub lists for the GitHub App. Does nothing when the App is not
      configured.
      """

      public? false

      run SyncAll
    end

    action :token, :string do
      description """
      Returns an installation token for the installation `installation_id`.
      The token stays valid for at least five more minutes. Only a POC can
      get it.
      """

      public? false

      argument :installation_id, :integer, allow_nil?: false

      run Token
    end

    action :public_read_token, :string do
      description """
      Returns the installation token of the GitHub App on the home
      organization. Anyone can get this token. Use it only for GET requests
      about public data that belongs to nobody in particular: the global
      advisory database, a profile lookup, the OTP versions table. Never use
      it for a request about a specific repository. This rule also applies
      to a repository in the home organization. Never use it for a request
      that is not a GET request.
      """

      public? false

      run PublicReadToken
    end
  end

  policies do
    # The scheduled sync runs with no actor. It reads freely, and its writes
    # carry the stamp of `Varsel.GitHub.Sync`.
    bypass AshObanInteraction do
      authorize_if action_type(:read)
      authorize_if action(:sync_all)
      forbid_unless action_type([:create, :update, :destroy])
      authorize_if context_equals([:private, :github_sync], true)
    end

    policy action_type(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if actor_attribute_equals(:system, :github_public_read)
      authorize_if expr(exists(user_installations, user_id == ^actor(:id)))
    end

    # Stamped by the person's own `Varsel.Accounts.User`
    # `:sync_github_installations`, which stores what their token lists.
    policy action(:sync) do
      forbid_unless context_equals([:private, :github_sync], true)
      authorize_if actor_present()
    end

    # Stamped by Varsel.GitHub.Installation.Mint.
    policy action(:store_token) do
      forbid_unless context_equals([:private, :github_sync], true)
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if actor_attribute_equals(:system, :github_public_read)
    end

    policy action(:token) do
      description "Only a POC acts with an installation token. This policy is the one place that rule lives."
      access_type :strict
      authorize_if actor_attribute_equals(:role, :poc)
    end

    policy action(:public_read_token) do
      authorize_if always()
    end
  end

  attributes do
    attribute :id, :integer do
      description "GitHub's id of the installation."
      primary_key? true
      allow_nil? false
      public? true
    end

    attribute :account, :ci_string do
      description "The login of the account the App is installed on."
      allow_nil? false
      public? true
    end

    attribute :kind, Kind do
      allow_nil? false
      public? true
    end

    attribute :repository_selection, RepositorySelection do
      allow_nil? false
      public? true
    end

    attribute :suspended_at, :utc_datetime_usec do
      description "When the account suspended the installation. GitHub mints no token for a suspended installation."
      allow_nil? true
      public? true
    end

    attribute :token, :string do
      sensitive? true
      allow_nil? true
      public? true
    end

    attribute :token_expires_at, :utc_datetime_usec do
      allow_nil? true
      public? true
    end

    attribute :synced_at, :utc_datetime_usec do
      description "When GitHub last listed the installation."
      allow_nil? false
      public? true
    end

    timestamps()
  end

  relationships do
    has_many :repositories, InstallationRepository do
      public? false
    end

    has_many :user_installations, UserInstallation do
      public? false
    end
  end
end
