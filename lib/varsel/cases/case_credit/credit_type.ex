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

  @doc """
  The credit types without repeats, in vocabulary order: the order the
  published record lists a person's roles in.
  """
  @spec sort([t()]) :: [t()]
  def sort(types), do: types |> Enum.uniq() |> Enum.sort_by(&rank/1)

  @doc "The place of a credit type in the vocabulary, for sorting credits by type."
  @spec rank(t()) :: non_neg_integer()
  def rank(type), do: Enum.find_index(values(), &(&1 == type))

  @precedence [
    :remediation_developer,
    :finder,
    :reporter,
    :analyst,
    :remediation_reviewer,
    :remediation_verifier,
    :coordinator,
    :sponsor,
    :tool,
    :other
  ]

  @doc """
  The one role that stands for a person where only one can, as on a GitHub
  advisory: the weightiest of the roles they carry. Writing the fix weighs
  most. Then come discovery, disclosure and analysis, then the roles around
  the fix, then coordination, funding and tooling.
  """
  @spec weightiest([t(), ...]) :: t()
  def weightiest([_type | _rest] = types) do
    Enum.min_by(types, &Enum.find_index(@precedence, fn type -> type == &1 end))
  end
end
