# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.WeaknessRelationship do
  @moduledoc """
  Join resource representing a directed relationship between two CWE weaknesses.

  Corresponds to `<Related_Weakness>` entries in the MITRE CWE XML catalog.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CWE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  alias Varsel.CWE.Weakness

  postgres do
    table "cwe_weakness_relationships"
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
      accept [:source_cwe_id, :target_cwe_id, :nature, :view_id, :ordinal]
      upsert? true
      upsert_fields [:nature, :view_id, :ordinal]
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
    attribute :source_cwe_id, :integer do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end

    attribute :target_cwe_id, :integer do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end

    attribute :nature, Varsel.CWE.RelatedWeakness.Nature do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end

    attribute :view_id, :integer do
      allow_nil? false
      primary_key? true
      writable? true
      public? true
    end

    attribute :ordinal, :string do
      allow_nil? true
      public? true
    end
  end

  relationships do
    belongs_to :source, Weakness do
      source_attribute :source_cwe_id
      destination_attribute :cwe_id
      define_attribute? false
      public? true
    end

    belongs_to :target, Weakness do
      source_attribute :target_cwe_id
      destination_attribute :cwe_id
      define_attribute? false
      public? true
    end
  end
end
