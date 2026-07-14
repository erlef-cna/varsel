# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.AttackPatternRelationship do
  @moduledoc """
  Join resource representing a directed relationship between two CAPEC attack patterns.

  Corresponds to `<Related_Attack_Pattern>` entries in the MITRE CAPEC XML catalog.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CAPEC,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  alias Varsel.CAPEC.AttackPattern

  postgres do
    table "capec_attack_pattern_relationships"
    repo Varsel.Repo

    references do
      reference :target, deferrable: :initially
    end
  end

  actions do
    read :read do
      primary? true
    end

    create :create do
      primary? true
      accept [:source_capec_id, :target_capec_id, :nature]
      upsert? true
      upsert_fields []
    end

    update :update do
      primary? true
      accept []
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
    attribute :source_capec_id, :integer do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end

    attribute :target_capec_id, :integer do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end

    attribute :nature, Varsel.CAPEC.RelatedAttackPattern.Nature do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end
  end

  relationships do
    belongs_to :source, AttackPattern do
      source_attribute :source_capec_id
      destination_attribute :capec_id
      define_attribute? false
      public? true
    end

    belongs_to :target, AttackPattern do
      source_attribute :target_capec_id
      destination_attribute :capec_id
      define_attribute? false
      public? true
    end
  end
end
