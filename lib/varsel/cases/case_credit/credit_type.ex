# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseCredit.CreditType do
  @moduledoc """
  The full CVE 5.2 `credits[].type` vocabulary. Multi-word values render with
  spaces (`:remediation_developer` → `"remediation developer"`).
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      :finder,
      :reporter,
      :analyst,
      :coordinator,
      :remediation_developer,
      :remediation_reviewer,
      :remediation_verifier,
      :sponsor,
      :tool,
      :other
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_credit_type

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_credit_type

  @doc "The CVE JSON representation of a credit type."
  @spec render(t()) :: String.t()
  def render(type), do: type |> to_string() |> String.replace("_", " ")
end
