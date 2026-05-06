# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts.GitHubAppToken do
  @moduledoc false

  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.Accounts,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshCloak, AshOban]

  alias CveManagement.GitHub.AppClient

  postgres do
    table "git_hub_app_tokens"
    repo CveManagement.Repo
  end

  cloak do
    vault(CveManagement.Vault)
    attributes([:access_token, :refresh_token])
  end

  oban do
    triggers do
      trigger :refresh do
        action :refresh
        where expr(status == :valid and expires_at <= ago(-10, :minute))
        worker_module_name CveManagement.Accounts.GitHubAppToken.RefreshWorker
        scheduler_module_name CveManagement.Accounts.GitHubAppToken.RefreshScheduler
        queue :github_advisory_sync
        max_attempts 3
        scheduler_cron "* * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end
  end

  actions do
    defaults [:read]

    create :upsert_from_oauth do
      accept [:access_token, :refresh_token, :expires_at]
      argument :user_id, :uuid, allow_nil?: false

      upsert? true
      upsert_identity :unique_user_id
      upsert_fields [:encrypted_access_token, :encrypted_refresh_token, :expires_at, :status]

      change set_attribute(:status, :valid)

      change fn changeset, _ ->
        Ash.Changeset.force_change_attribute(
          changeset,
          :user_id,
          Ash.Changeset.get_argument(changeset, :user_id)
        )
      end
    end

    update :refresh do
      require_atomic? false

      change fn changeset, _context ->
        Ash.Changeset.before_action(changeset, fn changeset ->
          require Logger

          token = Ash.load!(changeset.data, [:refresh_token], authorize?: false)

          case AppClient.refresh_token(token.refresh_token) do
            {:ok, %{access_token: access_token, refresh_token: refresh_token, expires_at: expires_at}} ->
              changeset
              |> AshCloak.encrypt_and_set(:access_token, access_token)
              |> AshCloak.encrypt_and_set(:refresh_token, refresh_token)
              |> Ash.Changeset.force_change_attribute(:expires_at, expires_at)
              |> Ash.Changeset.force_change_attribute(:status, :valid)

            {:error, reason} ->
              Logger.error("GitHubAppToken refresh failed: #{inspect(reason)}")
              Ash.Changeset.force_change_attribute(changeset, :status, :invalid)
          end
        end)
      end
    end

    update :mark_invalid do
      accept []
      change set_attribute(:status, :invalid)
    end

    destroy :disconnect do
      primary? true
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if expr(user_id == ^actor(:id))
    end

    policy action(:upsert_from_oauth) do
      authorize_if expr(^arg(:user_id) == ^actor(:id))
    end

    policy action(:mark_invalid) do
      authorize_if expr(user_id == ^actor(:id))
    end

    policy action(:disconnect) do
      authorize_if expr(user_id == ^actor(:id))
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :access_token, :string do
      allow_nil? false
      sensitive? true
    end

    attribute :refresh_token, :string do
      allow_nil? false
      sensitive? true
    end

    attribute :expires_at, :utc_datetime do
      allow_nil? false
      public? true
    end

    attribute :status, :atom do
      allow_nil? false
      default :valid
      constraints one_of: [:valid, :invalid]
      public? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :user, CveManagement.Accounts.User do
      allow_nil? false
      public? true
    end
  end

  identities do
    identity :unique_user_id, [:user_id]
  end
end
