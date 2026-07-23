# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.AttackPatternWeakness do
  @moduledoc """
  Join resource linking a CAPEC attack pattern to the CWE weaknesses it can exploit.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CAPEC,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  alias Varsel.CAPEC.AttackPattern

  postgres do
    table "capec_attack_pattern_weaknesses"
    repo Varsel.Repo
  end

  actions do
    read :read do
      primary? true
      description "List CAPEC attack-pattern to CWE weakness mappings."
    end

    create :create do
      primary? true
      description "Upsert a CAPEC-to-CWE mapping from the catalog sync."
      accept [:capec_id, :cwe_id]
      upsert? true
      upsert_fields []
    end

    destroy :destroy do
      primary? true
      description "Delete a CAPEC-to-CWE mapping."
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if always()
    end

    # These join rows have no independent lifecycle: they are only ever written
    # as a side effect of managing an AttackPattern's :weaknesses (the catalog
    # sync's manage_relationship), so authorize the write by that provenance.
    policy action_type([:create, :destroy]) do
      authorize_if accessing_from(AttackPattern, :weaknesses_join_assoc)
    end
  end

  # Pure MITRE-derived join table (rows come from the CAPEC catalog sync, not
  # user writes), so per-row created/updated timestamps carry no meaning.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
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
    belongs_to :attack_pattern, AttackPattern do
      source_attribute :capec_id
      destination_attribute :capec_id
      define_attribute? false
      allow_nil? false
      public? true
    end

    belongs_to :weakness, Varsel.CWE.Weakness do
      source_attribute :cwe_id
      destination_attribute :cwe_id
      define_attribute? false
      allow_nil? false
      public? true
    end
  end
end
