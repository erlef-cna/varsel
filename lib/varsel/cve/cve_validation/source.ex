# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidation.Source do
  @moduledoc false

  @behaviour AshGraphql.Type

  # :eef covers EEF/CNA policy requirements beyond the CVE schema and cvelint
  # (a title and a CVSS v4 metric are always required for our records).
  use Ash.Type.Enum, values: [:schema, :cvelint, :hex, :eef]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :cve_validation_source

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :cve_validation_source
end
