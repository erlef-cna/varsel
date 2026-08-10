# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE do
  @moduledoc false
  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain, AshAi, AshGraphql.Domain]

  alias Varsel.CWE.View
  alias Varsel.CWE.Weakness

  admin do
    show? true
  end

  tools do
    tool :list_weaknesses, Weakness, :read do
      select [:cwe_id, :name, :description]
    end

    tool :search_weaknesses, Weakness, :search do
      select [:cwe_id, :name, :description]
    end

    tool :get_weakness, Weakness, :get_by_cwe_id do
      select [
        :cwe_id,
        :name,
        :description,
        :extended_description,
        :potential_mitigations,
        :common_consequences
      ]
    end

    tool :get_weakness_related_weaknesses, Weakness, :get_by_cwe_id do
      select [:cwe_id, :name]

      load related_weakness_relationships: [
             :nature,
             source: [:cwe_id, :name],
             target: [:cwe_id, :name]
           ]

      load_strict? true
    end

    tool :get_weakness_related_attack_patterns, Weakness, :get_by_cwe_id do
      select [:cwe_id, :name]
      load related_attack_patterns: [:capec_id, :name, :description]
      load_strict? true
    end

    tool :list_cwe_views, View, :read do
      load [:member_weaknesses]
    end

    tool :get_cwe_view, View, :get_by_view_id do
      load [:member_weaknesses]
    end
  end

  graphql do
    queries do
      list Weakness, :list_weaknesses, :read
      get Weakness, :get_weakness, :get_by_cwe_id, identity: false
      list Weakness, :search_weaknesses, :search
      list View, :list_cwe_views, :read
      get View, :get_cwe_view, :get_by_view_id, identity: false
    end
  end

  resources do
    resource Weakness do
      define :list_weaknesses, action: :read
      define :get_weakness, action: :get_by_cwe_id, args: [:cwe_id]
      define :search_weaknesses, action: :search, args: [:query]
      define :upsert_weakness, action: :upsert
      define :sync_cwe_catalog, action: :sync_cwe_catalog
    end

    resource Varsel.CWE.WeaknessRelationship do
      define :list_weakness_relationships, action: :read
      define :list_weakness_children, action: :list_children
      define :list_weakness_parents, action: :list_parents
      define :create_weakness_relationship, action: :create
      define :update_weakness_relationship, action: :update
      define :destroy_weakness_relationship, action: :destroy
    end

    resource View do
      define :list_views, action: :read
      define :list_switchable_views, action: :list_switchable
      define :get_view, action: :get_by_view_id, args: [:view_id]
      define :upsert_view, action: :upsert
      define :destroy_view, action: :destroy
    end

    resource Varsel.CWE.ViewMembership do
      define :list_view_memberships, action: :read
      define :list_view_memberships_by_view, action: :list_by_view
      define :create_view_membership, action: :create
      define :destroy_view_membership, action: :destroy
    end

    resource Varsel.CWE.CweMetadata do
      define :read_cwe_metadata, action: :read
      define :upsert_cwe_metadata, action: :upsert
    end

    resource Varsel.CWE.WeaknessClosure do
      define :list_weakness_closure, action: :read
      define :refresh_weakness_closure, action: :refresh
      define :cwe_in_view?, action: :in_view?
    end
  end
end
