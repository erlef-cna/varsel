# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisoryWeakness do
  @moduledoc """
  Join resource linking a GitHub advisory to the CWE weaknesses it references.
  """

  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.ReportChannels,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  alias CveManagement.ReportChannels.GitHubAdvisory

  postgres do
    table "git_hub_advisory_weaknesses"
    repo CveManagement.Repo
  end

  actions do
    read :read do
      primary? true
    end

    create :create do
      primary? true
      accept [:ghsa_id, :cwe_id]
      upsert? true
      upsert_fields []
    end

    destroy :destroy do
      primary? true
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if accessing_from(GitHubAdvisory, :weaknesses)
    end

    policy action_type(:create) do
      authorize_if accessing_from(GitHubAdvisory, :weaknesses)
    end

    policy action_type(:destroy) do
      authorize_if accessing_from(GitHubAdvisory, :weaknesses)
    end
  end

  attributes do
    attribute :ghsa_id, :string do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end

    attribute :cwe_id, :integer do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end
  end

  relationships do
    belongs_to :advisory, GitHubAdvisory do
      source_attribute :ghsa_id
      destination_attribute :ghsa_id
      define_attribute? false
      public? true
    end

    belongs_to :weakness, CveManagement.CWE.Weakness do
      source_attribute :cwe_id
      destination_attribute :cwe_id
      define_attribute? false
      public? true
    end
  end
end
