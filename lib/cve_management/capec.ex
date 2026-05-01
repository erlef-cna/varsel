# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CAPEC do
  @moduledoc false
  use Ash.Domain, otp_app: :cve_management, extensions: [AshAdmin.Domain, AshAi]

  alias CveManagement.CAPEC.AttackPattern

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

  resources do
    resource AttackPattern
    resource CveManagement.CAPEC.AttackPatternWeakness
    resource CveManagement.CAPEC.AttackPatternRelationship
    resource CveManagement.CAPEC.CapecMetadata
  end
end
