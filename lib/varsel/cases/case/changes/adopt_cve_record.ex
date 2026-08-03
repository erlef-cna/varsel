# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.AdoptCveRecord do
  @moduledoc """
  Fills the new case from the adopted CVE record's CNA container and creates
  the child rows read out of it. See `Varsel.Cases.Case.Import` for what a
  container can and cannot be read back into.

  Attributes are force-set rather than accepted: adoption reads them off the
  record, so letting a caller pass their own would make the case claim a
  provenance it does not have.

  The record itself is left in whatever state it is in — adoption is a local
  editorial act, not a MITRE one.
  """

  use Ash.Resource.Change

  alias Varsel.CAPEC.AttackPattern
  alias Varsel.Cases.Case.Import
  alias Varsel.CVE
  alias Varsel.CWE.Weakness

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, &adopt(&1, context.actor))
  end

  defp adopt(changeset, actor) do
    cve_record_id = Ash.Changeset.get_argument(changeset, :cve_record_id)

    case CVE.get_cve_record(cve_record_id, actor: actor) do
      {:ok, record} ->
        changeset
        |> Ash.Changeset.force_change_attribute(:cve_record_id, record.id)
        |> Ash.Changeset.force_change_attributes(Import.case_params(record.cve_json))
        |> manage_children(Import.child_params(record.cve_json))

      {:error, error} ->
        Ash.Changeset.add_error(changeset, error)
    end
  end

  # Each child goes in through its own `:add` action, so the validations and
  # policies that apply to a POC adding the row by hand apply here too.
  defp manage_children(changeset, children) do
    changeset
    |> manage(:weaknesses, known(children.weaknesses, :cwe_id, Weakness))
    |> manage(:impacts, known(children.impacts, :capec_id, AttackPattern))
    |> manage(:references, children.references)
    |> manage(:credits, children.credits)
  end

  defp manage(changeset, _relationship, []), do: changeset

  defp manage(changeset, relationship, rows) do
    Ash.Changeset.manage_relationship(changeset, relationship, rows,
      type: :create,
      on_no_match: {:create, :add}
    )
  end

  # A CWE or CAPEC missing from the local catalog is dropped before the insert,
  # not after: adoption is one transaction, so a foreign-key violation would
  # take the whole case down with it rather than just the classification.
  defp known([], _key, _catalog), do: []

  defp known(rows, key, catalog) do
    ids = Enum.map(rows, &Map.fetch!(&1, key))

    present =
      catalog
      |> Ash.Query.filter(^ref(key) in ^ids)
      |> Ash.Query.select([key])
      |> Ash.read!()
      |> MapSet.new(&Map.fetch!(&1, key))

    Enum.filter(rows, &MapSet.member?(present, Map.fetch!(&1, key)))
  end
end
