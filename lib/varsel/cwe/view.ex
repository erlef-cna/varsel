# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.View do
  @moduledoc """
  Represents a single CWE View from the MITRE CWE catalog.

  A view is a curated slice or hierarchy over the weakness catalog (e.g.
  "Research Concepts", CWE-1000). Corresponds to `<View>` entries under
  `<Views>` in the MITRE CWE XML catalog. Synced by the same
  `sync_cwe_catalog` action that syncs `Weakness`; see
  `Varsel.CWE.CatalogSync` for the orchestration.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CWE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshGraphql.Resource]

  import Ash.Expr

  alias Varsel.CWE.View.Type
  alias Varsel.CWE.ViewMembership
  alias Varsel.CWE.Weakness

  graphql do
    type :cwe_view
  end

  postgres do
    table "cwe_views"
    repo Varsel.Repo
  end

  actions do
    read :read do
      primary? true
      description "Lists CWE views."
    end

    read :get_by_view_id do
      description "Fetches a single CWE view by its integer View ID."
      argument :view_id, :integer, allow_nil?: false
      get? true
      filter expr(view_id == ^arg(:view_id))
    end

    create :upsert do
      description "Upserts a CWE view parsed from the CWE XML catalog."
      accept [:view_id, :name, :type, :status, :objective]
      upsert? true
      upsert_fields [:name, :type, :status, :objective, :updated_at]
    end

    destroy :destroy do
      primary? true
      description "Deletes a CWE view MITRE has removed from the catalog."
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
    attribute :view_id, :integer do
      primary_key? true
      allow_nil? false
      writable? true
      public? true
      description "The numeric CWE View identifier (e.g. 1000 for Research Concepts)."
    end

    attribute :name, :string do
      allow_nil? false
      public? true
    end

    attribute :type, Type do
      allow_nil? false
      public? true
    end

    attribute :status, Weakness.Status do
      allow_nil? false
      public? true
    end

    attribute :objective, :string do
      allow_nil? false
      public? true
    end

    timestamps()
  end

  relationships do
    has_many :memberships, ViewMembership do
      source_attribute :view_id
      destination_attribute :view_id
      public? true
    end

    many_to_many :member_weaknesses, Weakness do
      through ViewMembership
      source_attribute :view_id
      source_attribute_on_join_resource :view_id
      destination_attribute :cwe_id
      destination_attribute_on_join_resource :cwe_id
      public? true
    end
  end
end
