# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC do
  @moduledoc false
  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain, AshAi, AshGraphql.Domain]

  alias Varsel.CAPEC.AttackPattern

  admin do
    show? true
  end

  tools do
    tool :list_attack_patterns, AttackPattern, :read do
      load [:weaknesses, :related_attack_pattern_relationships]
    end

    tool :get_attack_pattern, AttackPattern, :get_by_capec_id do
      load [:weaknesses, :related_attack_pattern_relationships]
    end

    tool :search_attack_patterns, AttackPattern, :search do
      load [:weaknesses, :related_attack_pattern_relationships]
    end
  end

  graphql do
    queries do
      list AttackPattern, :list_attack_patterns, :read
      get AttackPattern, :get_attack_pattern, :get_by_capec_id, identity: false
      list AttackPattern, :search_attack_patterns, :search
    end
  end

  resources do
    resource AttackPattern do
      define :list_attack_patterns, action: :read
      define :get_attack_pattern, action: :get_by_capec_id, args: [:capec_id]
      define :search_attack_patterns, action: :search, args: [:query]
      define :upsert_attack_pattern, action: :upsert
      define :sync_capec_catalog, action: :sync_capec_catalog
    end

    resource Varsel.CAPEC.AttackPatternWeakness do
      define :list_attack_pattern_weaknesses, action: :read
      define :create_attack_pattern_weakness, action: :create
      define :destroy_attack_pattern_weakness, action: :destroy
    end

    resource Varsel.CAPEC.AttackPatternRelationship do
      define :list_attack_pattern_relationships, action: :read
      define :create_attack_pattern_relationship, action: :create
      define :update_attack_pattern_relationship, action: :update
      define :destroy_attack_pattern_relationship, action: :destroy
    end

    resource Varsel.CAPEC.CapecMetadata do
      define :read_capec_metadata, action: :read
      define :upsert_capec_metadata, action: :upsert
    end
  end
end
