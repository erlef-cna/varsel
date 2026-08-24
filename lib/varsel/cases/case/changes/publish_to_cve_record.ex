# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.PublishToCveRecord do
  @moduledoc """
  The publish handoff: refreshes derivations, renders the case, validates the
  assembled record, and hands it to the CVE record publish machinery —
  `request_publish` for a first publish, `update` for an amendment of an
  already-published record. Any blocker or validation error aborts the
  transaction (the case stays in its previous state).
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, &publish(&1, context))
  end

  defp publish(changeset, context) do
    case_record = changeset.data
    actor = context.actor

    with :ok <- require_cve_record(case_record),
         {:ok, refreshed} <- Varsel.Cases.refresh_case_derivation(case_record, actor: actor),
         {:ok, %{preview: preview}} <- Ash.load(refreshed, [:preview], actor: actor),
         :ok <- check_blockers(preview.blockers),
         :ok <- check_validation(Varsel.CVE.validate_cve_record!(preview.cve_record)) do
      hand_to_cve_record(changeset, case_record, preview.cve_record, context)
    else
      {:error, messages} ->
        Enum.reduce(messages, changeset, fn message, changeset ->
          Ash.Changeset.add_error(changeset, field: :state, message: message)
        end)
    end
  end

  defp require_cve_record(%{cve_record_id: nil}) do
    {:error, ["no CVE ID assigned; run assign_cve_id first"]}
  end

  defp require_cve_record(_case_record), do: :ok

  defp check_blockers([]), do: :ok
  defp check_blockers(blockers), do: {:error, blockers}

  defp check_validation(%{valid: true}), do: :ok

  defp check_validation(%{errors: errors}) do
    {:error,
     Enum.map(errors, fn error ->
       "#{error.source}: #{error.path && error.path <> ": "}#{error.message}"
     end)}
  end

  defp hand_to_cve_record(changeset, case_record, cve_json, context) do
    actor = context.actor

    cve_record =
      Varsel.CVE.get_cve_record!(case_record.cve_record_id, Ash.Context.to_opts(context))

    action =
      case cve_record.state do
        :draft -> :request_publish
        :published -> :update
        :pending_update -> :update
        other -> {:invalid, other}
      end

    case action do
      {:invalid, state} ->
        Ash.Changeset.add_error(changeset,
          field: :state,
          message: "the backing CVE record is #{state}; it must be draft (first publish) or published (amendment)"
        )

      action ->
        case cve_record
             |> Ash.Changeset.for_update(action, %{cve_json: cve_json}, actor: actor)
             |> Ash.update() do
          {:ok, _record} -> changeset
          {:error, error} -> Ash.Changeset.add_error(changeset, error)
        end
    end
  end
end
