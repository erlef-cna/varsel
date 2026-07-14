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
    resource AttackPattern
    resource Varsel.CAPEC.AttackPatternWeakness
    resource Varsel.CAPEC.AttackPatternRelationship
    resource Varsel.CAPEC.CapecMetadata
  end
end
