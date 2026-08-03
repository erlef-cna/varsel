# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Validations.CveRecordAdoptable do
  @moduledoc """
  A CVE record can be adopted into a case once, and only while it still has a
  record to adopt.

  Stated as a validation rather than a precondition inside
  `Varsel.Cases.Case.Changes.AdoptCveRecord` so `Ash.can?/3` (with
  `validate?: true`) can answer whether the affordance belongs on screen —
  a change does not run while authorizing, a validation does. The
  `unique_cve_record` identity stays the race-proof enforcement.
  """

  use Ash.Resource.Validation

  alias Varsel.CVE

  @adoptable_states [:draft, :publishing, :published, :pending_update]

  @doc """
  The record states that have something for a case to manage.

  A reserved or withheld ID has no container to read back into, and a rejected
  one is a tombstone. Exposed so an affordance can ask the same question of a
  row it already holds instead of round-tripping to the database per row; this
  module stays the enforcement.
  """
  @spec adoptable_states() :: [atom()]
  def adoptable_states, do: @adoptable_states

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, context) do
    case Ash.Changeset.get_argument(changeset, :cve_record_id) do
      nil -> {:error, field: :cve_record_id, message: "is required"}
      cve_record_id -> validate_record(cve_record_id, context.actor)
    end
  end

  defp validate_record(cve_record_id, actor) do
    case CVE.get_cve_record(cve_record_id, load: [:case], actor: actor) do
      {:ok, %{case: %{}}} ->
        {:error, field: :cve_record_id, message: "already has a case"}

      {:ok, %{state: state}} when state not in @adoptable_states ->
        {:error,
         field: :cve_record_id, message: "a %{state} CVE record has nothing to manage as a case", vars: [state: state]}

      {:ok, _record} ->
        :ok

      {:error, _error} ->
        {:error, field: :cve_record_id, message: "does not exist"}
    end
  end
end
