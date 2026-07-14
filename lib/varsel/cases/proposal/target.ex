# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Target do
  @moduledoc """
  Which kind of resource a proposal addresses — the single registry of the
  polymorphic target mechanism.

  `target_id` semantics per operation:

  * `:set` — the row being changed; nil when the target is the case itself.
  * `:delete` — the row being removed (never nil, never `:case`).
  * `:insert` — the *parent* row: nil when the parent is the case,
    the `affected_package` id for `:package_channel` / `:version_event`.
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      :case,
      :affected_package,
      :package_channel,
      :version_event,
      :reference,
      :credit,
      :weakness,
      :impact
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_proposal_target

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_proposal_target

  @doc "The Ash resource module a target value addresses."
  @spec resource(t()) :: module()
  def resource(:case), do: Varsel.Cases.Case
  def resource(:affected_package), do: Varsel.Cases.AffectedPackage
  def resource(:package_channel), do: Varsel.Cases.PackageChannel
  def resource(:version_event), do: Varsel.Cases.VersionEvent
  def resource(:reference), do: Varsel.Cases.CaseReference
  def resource(:credit), do: Varsel.Cases.CaseCredit
  def resource(:weakness), do: Varsel.Cases.CaseWeakness
  def resource(:impact), do: Varsel.Cases.CaseImpact

  @doc "The parent kind of a target: nil for the case, :case or :affected_package for children."
  @spec parent(t()) :: t() | nil
  def parent(:case), do: nil
  def parent(:package_channel), do: :affected_package
  def parent(:version_event), do: :affected_package
  def parent(_target), do: :case

  @doc "The FK attribute pointing at the parent row on an inserted child."
  @spec parent_key(t()) :: atom() | nil
  def parent_key(:case), do: nil
  def parent_key(:package_channel), do: :affected_package_id
  def parent_key(:version_event), do: :affected_package_id
  def parent_key(_target), do: :case_id
end
