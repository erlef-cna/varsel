# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.DerivedReference do
  @moduledoc """
  One reference the published record adds on its own — a `cna.erlef.org` /
  `osv.dev` self-link or a fix-commit link — as read back off the rendered
  container by `Varsel.Cases.Case.Calculations.DerivedReferences`.

  Read-only by nature: these are never stored (that is
  `Varsel.Cases.CaseReference`) and never accepted as input, so the type exists
  to give the calculation a real shape rather than a bare map.
  """

  use Ash.Resource,
    data_layer: :embedded,
    extensions: [AshGraphql.Resource]

  graphql do
    type :case_derived_reference
  end

  attributes do
    attribute :url, :string do
      description "The reference URL the record will carry."
      allow_nil? false
      public? true
    end

    attribute :tags, {:array, :string} do
      description "CVE reference tags the renderer assigned (e.g. [\"patch\"])."
      allow_nil? false
      default []
      public? true
    end
  end
end
