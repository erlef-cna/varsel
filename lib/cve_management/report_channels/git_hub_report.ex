# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubReport do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.ReportChannels,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "git_hub_reports"
    repo CveManagement.Repo
  end

  actions do
    defaults [
      :read,
      create: [
        :github_advisory_id,
        :repository,
        :title,
        :body,
        :severity,
        :raw_payload,
        :processed_at
      ],
      update: [
        :github_advisory_id,
        :repository,
        :title,
        :body,
        :severity,
        :raw_payload,
        :processed_at
      ]
    ]
  end

  attributes do
    uuid_primary_key :id

    attribute :github_advisory_id, :string do
      allow_nil? false
      public? true
    end

    attribute :repository, :string do
      allow_nil? false
      public? true
    end

    attribute :title, :string do
      allow_nil? false
      public? true
    end

    attribute :body, :string do
      allow_nil? false
      public? true
    end

    attribute :severity, :string do
      public? true
    end

    attribute :raw_payload, :map do
      allow_nil? false
      public? true
    end

    attribute :processed_at, :utc_datetime do
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, CveManagement.Cases.Case do
      public? true
      allow_nil? true
    end
  end
end
