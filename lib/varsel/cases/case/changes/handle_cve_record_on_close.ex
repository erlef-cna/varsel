# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.HandleCveRecordOnClose do
  @moduledoc """
  Closing a case that has a CVE ID assigned decides what becomes of the ID:

  * `reject_cve_id: true` rejects the ID at MITRE (burns it) via
    `Varsel.CVE.CveRecord`'s `:reject`. The case keeps its link to the
    rejected record.
  * otherwise a drafted ID returns to the pool via `:release`, and the case
    lets go of it. A record in any other state stays linked as it is.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.CVE

  @impl Ash.Resource.Change
  def change(%{data: %{cve_record_id: nil}} = changeset, _opts, _context), do: changeset

  def change(changeset, _opts, context) do
    changeset
    |> Changeset.before_action(&decide(&1, context))
    |> Changeset.after_action(&release(&1, &2, context))
  end

  defp decide(changeset, context) do
    if Changeset.get_argument(changeset, :reject_cve_id) do
      reject(changeset, context)
    else
      unlink(changeset, context)
    end
  end

  defp reject(changeset, context) do
    reason = Changeset.get_attribute(changeset, :closed_reason) || "Case closed"

    cve_record = CVE.get_cve_record!(changeset.data.cve_record_id, Ash.Context.to_opts(context))

    case CVE.reject_cve_record(cve_record, %{rejection_reason: reason}, actor: context.actor) do
      {:ok, _} -> changeset
      {:error, error} -> Changeset.add_error(changeset, error)
    end
  end

  # `:release` refuses an ID a case holds, so the link goes with the case row
  # and the release follows it in the same transaction.
  defp unlink(changeset, context) do
    case CVE.get_cve_record(changeset.data.cve_record_id, Ash.Context.to_opts(context)) do
      {:ok, %{state: :draft} = record} ->
        changeset
        |> Changeset.force_change_attribute(:cve_record_id, nil)
        |> Changeset.put_context(:releasing_cve_record, record)

      {:ok, _record} ->
        changeset

      {:error, error} ->
        Changeset.add_error(changeset, error)
    end
  end

  defp release(%{context: %{releasing_cve_record: record}}, case_record, context) do
    case CVE.release_cve_record(record, %{}, Ash.Context.to_opts(context)) do
      {:ok, _released} -> {:ok, case_record}
      {:error, error} -> {:error, error}
    end
  end

  defp release(_changeset, case_record, _context), do: {:ok, case_record}
end
