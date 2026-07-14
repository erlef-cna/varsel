# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.RelatedAttackPattern do
  @moduledoc """
  Embedded struct representing a relationship from one CAPEC attack pattern to another.

  Stored as elements of `AttackPattern.related_attack_patterns` (a jsonb array column).
  The `nature` field is typed via `Nature` enum; raw XML values like "ChildOf"
  are mapped to snake_case atoms on ingest.
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :nature, Varsel.CAPEC.RelatedAttackPattern.Nature do
      allow_nil? false
      public? true
    end

    attribute :capec_id, :integer do
      allow_nil? false
      public? true
      description "Integer ID of the related attack pattern (e.g. 66 for CAPEC-66)."
    end
  end
end
