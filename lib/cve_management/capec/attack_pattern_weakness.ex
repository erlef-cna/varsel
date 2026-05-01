# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CAPEC.AttackPatternWeakness do
  @moduledoc """
  Join resource linking a CAPEC attack pattern to the CWE weaknesses it can exploit.
  """

  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.CAPEC,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "capec_attack_pattern_weaknesses"
    repo CveManagement.Repo
  end

  actions do
    read :read do
      primary? true
    end

    create :create do
      primary? true
      accept [:capec_id, :cwe_id]
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
      authorize_if always()
    end
  end

  attributes do
    attribute :capec_id, :integer do
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
    belongs_to :attack_pattern, CveManagement.CAPEC.AttackPattern do
      source_attribute :capec_id
      destination_attribute :capec_id
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
