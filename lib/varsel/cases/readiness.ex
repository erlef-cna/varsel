# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Readiness do
  @moduledoc """
  Heuristic per-section readiness of a case, feeding the workspace's section
  rail: which parts of the record still need work before publishing is worth
  attempting.

  Deliberately lighter than `Varsel.Cases.Publication` — that pipeline runs
  the authoritative schema/cvelint/hex validation on the rendered record;
  this module answers "is the section filled in?" from the loaded case alone
  so the rail can show it on every render without rendering the record.
  """

  alias Varsel.Cases.Case

  @type status :: :ok | :attention | nil

  @doc """
  Per-section readiness. `nil` status means the section is optional and
  empty — no marker either way. The case must have its child tree loaded.
  """
  @spec sections(Case.t()) :: [%{id: String.t(), label: String.t(), status: status()}]
  def sections(case_record) do
    [
      %{id: "summary", label: "Summary", status: summary_status(case_record)},
      %{id: "severity", label: "Severity", status: required(not is_nil(case_record.cvss_v4))},
      %{id: "affected", label: "Affected", status: affected_status(case_record)},
      %{id: "references", label: "References", status: required(case_record.references != [])},
      %{id: "credits", label: "Credits", status: optional(case_record.credits != [])},
      %{id: "weaknesses", label: "Weaknesses", status: required(case_record.weaknesses != [])},
      %{id: "impacts", label: "Impacts", status: optional(case_record.impacts != [])}
    ]
  end

  defp summary_status(case_record) do
    required(present?(case_record.description_md))
  end

  defp affected_status(%{affected_packages: []}), do: :attention

  defp affected_status(%{affected_packages: packages}) do
    if Enum.any?(packages, &(derivation_issues(&1) != [])), do: :attention, else: :ok
  end

  defp derivation_issues(%{derivation_cache: nil}), do: []

  defp derivation_issues(%{derivation_cache: cache}) do
    channel_issues =
      cache
      |> Map.get("channels", %{})
      |> Map.values()
      |> Enum.flat_map(&(&1["issues"] || []))

    (cache["issues"] || []) ++ channel_issues
  end

  defp required(true), do: :ok
  defp required(false), do: :attention

  defp optional(true), do: :ok
  defp optional(false), do: nil

  defp present?(nil), do: false
  defp present?(value), do: String.trim(value) != ""
end
