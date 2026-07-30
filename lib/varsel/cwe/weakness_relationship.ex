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

  alias Varsel.CWE.View
  alias Varsel.CWE.Weakness

  postgres do
    table "cwe_weakness_relationships"
    repo Varsel.Repo

    references do
      reference :target, deferrable: :initially

      # Pure catalog-derived join row, unlike :source/:target (which point at
      # Weakness and must never silently vanish just because MITRE prunes a
      # view) — safe to let the DB cascade so the sync doesn't have to order
      # around it.
      reference :view, deferrable: :initially, on_delete: :delete
    end
  end

  actions do
    read :read do
      primary? true
      description "List directed relationships between CWE weaknesses."
    end

    create :create do
      primary? true
      description "Upsert a directed CWE weakness relationship from the catalog sync."
      accept [:source_cwe_id, :target_cwe_id, :nature, :view_id, :ordinal]
      upsert? true
      upsert_fields [:nature, :view_id, :ordinal]
    end

    update :update do
      primary? true
      description "Update a CWE weakness relationship."
      accept []
    end

    destroy :destroy do
      primary? true
      description "Delete a CWE weakness relationship."
    end
  end

  policies do
    policy action_type(:read) do
      authorize_if always()
    end

    # These rows have no independent lifecycle: they are only ever written by
    # the catalog sync's flat diff, which stamps the accessing_from context of
    # the Weakness relationship it maintains.
    policy action_type([:create, :update, :destroy]) do
      authorize_if accessing_from(Weakness, :related_weakness_relationships)
    end
  end

  # Pure MITRE-derived join table (rows come from the CWE catalog sync, not
  # user writes), so per-row created/updated timestamps carry no meaning.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
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
      allow_nil? false
      public? true
    end

    belongs_to :target, Weakness do
      source_attribute :target_cwe_id
      destination_attribute :cwe_id
      define_attribute? false
      allow_nil? false
      public? true
    end

    belongs_to :view, View do
      source_attribute :view_id
      destination_attribute :view_id
      define_attribute? false
      allow_nil? false
      public? true
    end
  end
end
