# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.RelatedWeakness do
  @moduledoc """
  Embedded struct representing a single relationship from one CWE to another.

  Stored as elements of `Weakness.related_weaknesses` (a jsonb array column).
  The `nature` field is typed via `Nature` enum; raw XML values like "ChildOf"
  are mapped to snake_case atoms on ingest.
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :nature, Varsel.CWE.RelatedWeakness.Nature do
      allow_nil? false
      public? true
    end

    attribute :cwe_id, :integer do
      allow_nil? false
      public? true
      description "Integer ID of the related weakness (e.g. 74 for CWE-74)."
    end

    attribute :view_id, :integer do
      allow_nil? false
      public? true
      description "View context for this relationship (e.g. 1000 for Research Concepts)."
    end

    attribute :ordinal, :string do
      allow_nil? true
      public? true
      description "Primary or nil — indicates the primary parent in the hierarchy."
    end
  end
end
