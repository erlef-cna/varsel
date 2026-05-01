# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.AI.AiSkillRun do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.AI,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "ai_skill_runs"
    repo CveManagement.Repo
  end

  actions do
    defaults [:read, create: [:skill, :input_snapshot, :output, :model, :status]]
  end

  attributes do
    uuid_primary_key :id

    attribute :skill, :atom do
      allow_nil? false
      public? true
    end

    attribute :input_snapshot, :map do
      allow_nil? false
      public? true
    end

    attribute :output, :map do
      public? true
    end

    attribute :model, :string do
      allow_nil? false
      public? true
    end

    attribute :status, :atom do
      allow_nil? false
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, CveManagement.Cases.Case do
      public? true
      allow_nil? false
    end
  end
end
