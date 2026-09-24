# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidation.Error do
  @moduledoc """
  A single validation finding for a CVE record.
  """

  use Ash.Resource, data_layer: :embedded, extensions: [AshGraphql.Resource]

  graphql do
    type :cve_validation_error
  end

  attributes do
    attribute :source, Varsel.CVE.CveValidation.Source do
      description "Which validator produced this finding."
      allow_nil? false
      public? true
    end

    attribute :code, :string do
      description ~s{Stable finding code, e.g. "E017" (cvelint) or "EEF002" (policy). Nil for uncoded findings.}
      allow_nil? true
      public? true
    end

    attribute :path, :string do
      description "JSON path of the offending element, when known."
      allow_nil? true
      public? true
    end

    attribute :message, :string do
      allow_nil? false
      public? true
    end
  end
end
