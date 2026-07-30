# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.ViewMembership do
  @moduledoc """
  Join resource linking a CWE View to its member weaknesses.

  Corresponds to `<Has_Member>` entries under a `<View>`'s `<Members>` in the
  MITRE CWE XML catalog.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CWE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  alias Varsel.CWE.View
  alias Varsel.CWE.Weakness

  postgres do
    table "cwe_view_memberships"
    repo Varsel.Repo

    references do
      # Pure catalog-derived join row — safe to let the DB cascade when its
      # view disappears, unlike a case's weakness link.
      reference :view, on_delete: :delete
    end
  end

  actions do
    read :read do
      primary? true
      description "List CWE view to weakness membership mappings."
    end

    create :create do
      primary? true
      description "Upsert a CWE view membership from the catalog sync."
      accept [:view_id, :cwe_id]
      upsert? true
      upsert_fields []
    end

    destroy :destroy do
      primary? true
      description "Delete a CWE view membership."
    end
  end

  policies do
    policy action_type(:read) do
      authorize_if always()
    end

    # These join rows have no independent lifecycle: they are only ever
    # written by the catalog sync's flat diff, which stamps the
    # accessing_from context of the View relationship it maintains.
    policy action_type([:create, :destroy]) do
      authorize_if accessing_from(View, :member_weaknesses)
    end
  end

  # Pure MITRE-derived join table (rows come from the CWE catalog sync, not
  # user writes), so per-row created/updated timestamps carry no meaning.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
  attributes do
    attribute :view_id, :integer do
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
    belongs_to :view, View do
      source_attribute :view_id
      destination_attribute :view_id
      define_attribute? false
      allow_nil? false
      public? true
    end

    belongs_to :weakness, Weakness do
      source_attribute :cwe_id
      destination_attribute :cwe_id
      define_attribute? false
      allow_nil? false
      public? true
    end
  end
end
