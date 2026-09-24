# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidation.Result do
  @moduledoc """
  Aggregated result of validating a CVE record.
  """

  use Ash.Resource, data_layer: :embedded, extensions: [AshGraphql.Resource]

  graphql do
    type :cve_validation_result
  end

  attributes do
    attribute :valid, :boolean do
      allow_nil? false
      public? true
    end

    attribute :errors, {:array, Varsel.CVE.CveValidation.Error} do
      allow_nil? false
      default []
      public? true
    end
  end
end
