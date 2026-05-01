# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.ApiReport do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.ReportChannels,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "api_reports"
    repo CveManagement.Repo
  end

  actions do
    defaults [:read, create: [:api_key_id, :payload, :processed_at]]
  end

  attributes do
    uuid_primary_key :id

    attribute :api_key_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :payload, :map do
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
