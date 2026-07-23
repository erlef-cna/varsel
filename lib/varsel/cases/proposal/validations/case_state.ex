# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Validations.CaseState do
  @moduledoc """
  Guards proposal actions by the parent case's lifecycle state:

  * `:propose` — allowed in every state except the terminal `:closed`
    (post-publish enrichment proposals are a core flow).
  * `:accept` / `:decline` — only while the case content is editable
    (`:draft` / `:review`); a published case must be reopened first.
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, opts, _context) do
    allowed = Keyword.fetch!(opts, :states)
    message = Keyword.fetch!(opts, :message)
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)

    case fetch_case_state(case_id) do
      {:ok, state} ->
        if state in allowed do
          :ok
        else
          {:error, field: :case_id, message: message, vars: [state: state]}
        end

      :error ->
        {:error, field: :case_id, message: "case does not exist"}
    end
  end

  defp fetch_case_state(nil), do: :error

  defp fetch_case_state(case_id) do
    case Varsel.Cases.get_case(case_id, authorize?: false) do
      {:ok, %{state: state}} -> {:ok, state}
      {:error, _} -> :error
    end
  end
end
