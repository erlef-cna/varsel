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
  alias Varsel.CWE.WeaknessClosure

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

    read :list_switchable do
      description """
      Lists views usable as a switch destination from the common-weaknesses
      browser: ones with at least one declared member (a view with nothing
      to show has nowhere for the browser to land) and not deprecated or
      obsolete, name ascending.
      """

      prepare build(sort: [name: :asc])

      filter expr(exists(memberships, true) and status not in [:deprecated, :obsolete])
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

    # The view-root closure rows (parent_cwe_id IS NULL). Each row's
    # descendant_cwe_id is a CWE reachable from the view's declared members,
    # counting recursively through the whole view — see WeaknessClosure's
    # moduledoc for the NULL-parent semantics.
    has_many :closure, WeaknessClosure do
      source_attribute :view_id
      destination_attribute :view_id
      filter expr(is_nil(parent_cwe_id))
      public? true
    end

    many_to_many :flat_member_weaknesses, Weakness do
      through WeaknessClosure
      source_attribute :view_id
      source_attribute_on_join_resource :view_id
      destination_attribute :cwe_id
      destination_attribute_on_join_resource :descendant_cwe_id
      join_relationship :closure
      public? true

      description """
      Every weakness reachable anywhere in the view, flattened across the
      whole hierarchy (not just declared root members) — derived from the
      NULL-parent closure rows via the :closure relationship.
      """
    end
  end
end
