# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Cases.Case do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "cases"
    repo CveManagement.Repo
  end

  actions do
    defaults [:read]
  end

  attributes do
    uuid_primary_key :id

    attribute :title, :string do
      public? true
    end

    attribute :severity_estimate, :atom do
      public? true
    end

    attribute :status, :atom do
      allow_nil? false
      public? true
    end

    attribute :published_at, :utc_datetime do
      public? true
    end

    attribute :approved_at, :utc_datetime do
      public? true
    end

    attribute :rejected_at, :utc_datetime do
      public? true
    end

    attribute :rejection_reason, :string do
      public? true
    end

    attribute :reporter_email, :string do
      public? true
    end

    attribute :reporter_name, :string do
      public? true
    end

    attribute :sla_deadline_accept, :utc_datetime do
      public? true
    end

    attribute :sla_deadline_feedback, :utc_datetime do
      public? true
    end

    attribute :sla_deadline_publish, :utc_datetime do
      public? true
    end

    attribute :publicly_exploited, :boolean do
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :approved_by, CveManagement.Accounts.User do
      public? true
      attribute_type :uuid
    end

    has_many :threads, CveManagement.Cases.CaseThread do
      public? true
      destination_attribute :case_id
    end

    has_many :assignments, CveManagement.Accounts.CaseAssignment do
      public? true
      destination_attribute :case_id
    end

    has_one :cve_reservation, CveManagement.CVE.CveReservation do
      public? true
      destination_attribute :case_id
    end

    has_many :cve_records, CveManagement.CVE.CveRecord do
      public? true
      destination_attribute :case_id
    end

    has_many :ai_skill_runs, CveManagement.AI.AiSkillRun do
      public? true
      destination_attribute :case_id
    end
  end
end
