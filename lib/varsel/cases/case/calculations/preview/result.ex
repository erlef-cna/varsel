# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.Preview.Result do
  @moduledoc """
  Outcome of rendering a case for preview: the full CVE 5.2 record plus which
  override hatches fired and the conditions that block publishing.
  """

  use Ash.Resource, data_layer: :embedded, extensions: [AshGraphql.Resource]

  graphql do
    type :case_preview_result
  end

  attributes do
    attribute :cve_record, :map do
      description "The full CVE 5.2 record (with a placeholder cveId until one is assigned)."
      allow_nil? false
      public? true
    end

    attribute :overrides_applied, {:array, :string} do
      description "Which render escape hatches fired (e.g. cna_override)."
      allow_nil? false
      default []
      public? true
    end

    attribute :blockers, {:array, :string} do
      description "Derivation-level problems that block publishing (pending fixes, git/channel issues)."
      allow_nil? false
      default []
      public? true
    end

    attribute :osv_record, :map do
      description """
      The OSV document the record would publish as, hex.pm versions included.
      Nil when the record has no OSV representation; see osv_status.
      """

      public? true
    end

    attribute :osv_status, :string do
      description "Why osv_record is nil."
      public? true
    end
  end
end
