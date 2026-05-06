# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.ReportChannels,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban]

  alias CveManagement.Accounts.User
  alias CveManagement.ReportChannels.GitHubAdvisory.Changes.FetchUrl
  alias CveManagement.ReportChannels.GitHubAdvisory.Changes.ParseJson
  alias CveManagement.ReportChannels.GitHubAdvisory.CollaboratingTeam
  alias CveManagement.ReportChannels.GitHubAdvisory.Credit
  alias CveManagement.ReportChannels.GitHubAdvisory.CreditDetailed
  alias CveManagement.ReportChannels.GitHubAdvisory.CvssSeverities
  alias CveManagement.ReportChannels.GitHubAdvisory.GitHubUser
  alias CveManagement.ReportChannels.GitHubAdvisory.Identifier
  alias CveManagement.ReportChannels.GitHubAdvisory.PrivateFork
  alias CveManagement.ReportChannels.GitHubAdvisory.Severity
  alias CveManagement.ReportChannels.GitHubAdvisory.State
  alias CveManagement.ReportChannels.GitHubAdvisory.Submission
  alias CveManagement.ReportChannels.GitHubAdvisory.VulnerablePackage

  postgres do
    table "git_hub_advisories"
    repo CveManagement.Repo
  end

  oban do
    triggers do
      trigger :refresh do
        action :refresh
        where expr(state in [:draft, :triage] and github_updated_at <= ago(1, :hour))
        worker_module_name CveManagement.ReportChannels.GitHubAdvisory.RefreshWorker
        scheduler_module_name CveManagement.ReportChannels.GitHubAdvisory.RefreshScheduler
        queue :github_advisory_sync
        max_attempts 3
        scheduler_cron "*/30 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end
  end

  code_interface do
    define :ingest_json, action: :ingest_json
    define :ingest_url, action: :ingest_url
  end

  actions do
    defaults [:read]

    create :ingest_json do
      accept [:fetched_by_user_id]

      skip_unknown_inputs :*

      argument :raw_data, :map, allow_nil?: false
      argument :weakness_ids, {:array, :integer}, allow_nil?: true, default: [], public?: false

      upsert? true

      upsert_fields [
        :cve_id,
        :summary,
        :description,
        :severity,
        :state,
        :url,
        :html_url,
        :author,
        :publisher,
        :github_created_at,
        :github_updated_at,
        :github_published_at,
        :github_closed_at,
        :github_withdrawn_at,
        :vulnerabilities,
        :cvss_severities,
        :identifiers,
        :credits,
        :credits_detailed,
        :collaborating_users,
        :collaborating_teams,
        :submission,
        :private_fork,
        :updated_at
      ]

      change ParseJson

      change manage_relationship(:weakness_ids, :weaknesses,
               type: :append_and_remove,
               on_lookup: :relate,
               on_no_match: :ignore,
               on_missing: :unrelate,
               value_is_key: :cwe_id
             )
    end

    create :ingest_url do
      accept [:fetched_by_user_id]

      skip_unknown_inputs :*

      argument :url, :string, allow_nil?: false
      argument :raw_data, :map, allow_nil?: true, public?: false
      argument :weakness_ids, {:array, :integer}, allow_nil?: true, default: [], public?: false

      upsert? true

      upsert_fields [
        :cve_id,
        :summary,
        :description,
        :severity,
        :state,
        :url,
        :html_url,
        :author,
        :publisher,
        :github_created_at,
        :github_updated_at,
        :github_published_at,
        :github_closed_at,
        :github_withdrawn_at,
        :vulnerabilities,
        :cvss_severities,
        :identifiers,
        :credits,
        :credits_detailed,
        :collaborating_users,
        :collaborating_teams,
        :submission,
        :private_fork,
        :updated_at
      ]

      change FetchUrl
      change ParseJson

      change manage_relationship(:weakness_ids, :weaknesses,
               type: :append_and_remove,
               on_lookup: :relate,
               on_no_match: :ignore,
               on_missing: :unrelate,
               value_is_key: :cwe_id
             )
    end

    read :fetch_by_ghsa_id do
      get? true
      argument :ghsa_id, :string, allow_nil?: false
      filter expr(ghsa_id == ^arg(:ghsa_id))
    end

    update :refresh do
      require_atomic? false

      skip_unknown_inputs :*

      argument :raw_data, :map, allow_nil?: true, public?: false
      argument :url, :string, allow_nil?: true, public?: false
      argument :weakness_ids, {:array, :integer}, allow_nil?: true, default: [], public?: false

      change fn changeset, _context ->
        Ash.Changeset.force_set_argument(changeset, :url, changeset.data.url)
      end

      change FetchUrl
      change ParseJson

      change manage_relationship(:weakness_ids, :weaknesses,
               type: :append_and_remove,
               on_lookup: :relate,
               on_no_match: :ignore,
               on_missing: :unrelate,
               value_is_key: :cwe_id
             )
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(fetched_by_user_id == ^actor(:id))

      authorize_if expr(
                     not is_nil(case_id) and
                       exists(case.assignments, user_id == ^actor(:id))
                   )

      authorize_if expr(has_collaborating_user(github_handle: ^actor(:github_handle)))
    end

    policy action([:ingest_json, :ingest_url]) do
      authorize_if always()
    end
  end

  attributes do
    attribute :ghsa_id, :string do
      primary_key? true
      allow_nil? false
      public? true
      writable? true
    end

    attribute :cve_id, :string do
      allow_nil? true
      public? true
    end

    attribute :summary, :string do
      allow_nil? false
      public? true
      constraints max_length: 1024
    end

    attribute :description, :string do
      allow_nil? true
      public? true
      constraints max_length: 65_535
    end

    attribute :severity, Severity do
      allow_nil? true
      public? true
    end

    attribute :state, State do
      allow_nil? false
      public? true
    end

    attribute :url, :string do
      allow_nil? false
      public? true
    end

    attribute :html_url, :string do
      allow_nil? false
      public? true
    end

    attribute :author, GitHubUser do
      allow_nil? true
      public? true
    end

    attribute :publisher, GitHubUser do
      allow_nil? true
      public? true
    end

    attribute :github_created_at, :utc_datetime do
      allow_nil? true
      public? true
    end

    attribute :github_updated_at, :utc_datetime do
      allow_nil? true
      public? true
    end

    attribute :github_published_at, :utc_datetime do
      allow_nil? true
      public? true
    end

    attribute :github_closed_at, :utc_datetime do
      allow_nil? true
      public? true
    end

    attribute :github_withdrawn_at, :utc_datetime do
      allow_nil? true
      public? true
    end

    attribute :vulnerabilities, {:array, VulnerablePackage} do
      allow_nil? true
      public? true
    end

    attribute :cvss_severities, CvssSeverities do
      allow_nil? true
      public? true
    end

    attribute :identifiers, {:array, Identifier} do
      allow_nil? true
      public? true
    end

    attribute :credits, {:array, Credit} do
      allow_nil? true
      public? true
    end

    attribute :credits_detailed, {:array, CreditDetailed} do
      allow_nil? true
      public? true
    end

    attribute :collaborating_users, {:array, GitHubUser} do
      allow_nil? true
      public? true
    end

    attribute :collaborating_teams, {:array, CollaboratingTeam} do
      allow_nil? true
      public? true
    end

    attribute :submission, Submission do
      allow_nil? true
      public? true
    end

    attribute :private_fork, PrivateFork do
      allow_nil? true
      public? true
    end

    attribute :processed_at, :utc_datetime do
      allow_nil? true
      public? true
    end

    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :fetched_by_user, User do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :case, CveManagement.Cases.Case do
      allow_nil? true
      public? true
    end

    many_to_many :weaknesses, CveManagement.CWE.Weakness do
      through CveManagement.ReportChannels.GitHubAdvisoryWeakness
      source_attribute :ghsa_id
      source_attribute_on_join_resource :ghsa_id
      destination_attribute :cwe_id
      destination_attribute_on_join_resource :cwe_id
      public? true
    end
  end

  calculations do
    calculate :has_collaborating_user,
              :boolean,
              expr(
                fragment(
                  "EXISTS (SELECT 1 FROM unnest(?) elem WHERE elem->>'login' = ?)",
                  collaborating_users,
                  ^arg(:github_handle)
                )
              ) do
      argument :github_handle, :string, allow_nil?: true
    end
  end
end
