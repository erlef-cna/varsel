# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubWatchedTarget do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.ReportChannels,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban]

  alias CveManagement.Accounts.GitHubAppToken
  alias CveManagement.Accounts.User
  alias CveManagement.GitHub.AdvisoryClient
  alias CveManagement.ReportChannels.GitHubAdvisory

  postgres do
    table "git_hub_watched_targets"
    repo CveManagement.Repo
  end

  oban do
    triggers do
      trigger :sync do
        action :sync
        where expr(is_nil(synced_at) or synced_at <= ago(30, :minute))
        worker_module_name CveManagement.ReportChannels.GitHubWatchedTarget.SyncWorker
        scheduler_module_name CveManagement.ReportChannels.GitHubWatchedTarget.SyncScheduler
        queue :github_advisory_sync
        max_attempts 3
        scheduler_cron "* * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end
  end

  code_interface do
    define :create, action: :create
    define :destroy, action: :destroy
  end

  actions do
    defaults [:read]

    create :create do
      accept [:owner, :repo, :user_id]

      change run_oban_trigger(:sync)
    end

    destroy :destroy do
      primary? true
    end

    update :sync do
      require_atomic? false

      change set_attribute(:synced_at, &DateTime.utc_now/0)

      change fn changeset, _context ->
        Ash.Changeset.before_action(changeset, fn changeset ->
          target = changeset.data

          user = Ash.get!(User, target.user_id, authorize?: false)

          token =
            Ash.get!(GitHubAppToken, [user_id: user.id],
              authorize?: false,
              domain: CveManagement.Accounts
            )

          loaded_token = Ash.load!(token, [:access_token], authorize?: false)

          {:ok, advisories} =
            if target.repo do
              AdvisoryClient.fetch_repository_advisories(
                loaded_token.access_token,
                target.owner,
                target.repo
              )
            else
              AdvisoryClient.fetch_org_advisories(loaded_token.access_token, target.owner)
            end

          for data <- advisories do
            GitHubAdvisory.ingest_json!(
              %{fetched_by_user_id: user.id, raw_data: data},
              authorize?: false
            )
          end

          changeset
        end)
      end
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if relates_to_actor_via(:user)
    end

    policy action(:create) do
      authorize_if relating_to_actor(:user)
    end

    policy action(:destroy) do
      authorize_if relates_to_actor_via(:user)
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :owner, :string do
      allow_nil? false
      public? true
    end

    attribute :repo, :string do
      allow_nil? true
      public? true
    end

    attribute :synced_at, :utc_datetime do
      allow_nil? true
      public? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :user, User do
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_target, [:user_id, :owner, :repo]
  end
end
