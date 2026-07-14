# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Render.CvssV4 do
  @moduledoc """
  Expands a CVSS v4.0 vector into the full `cvssV4_0` metric object of the
  CVE 5.2 schema (as published in every EEF record): base metrics from the
  vector, supplemental metrics defaulting to NOT_DEFINED, and threat /
  environmental metrics only when the vector defines them.
  """

  alias Varsel.Types.CVSS

  # {vector code, JSON field, always emitted?, code → JSON value}
  @base [
    {"AV", "attackVector", %{"N" => "NETWORK", "A" => "ADJACENT", "L" => "LOCAL", "P" => "PHYSICAL"}},
    {"AC", "attackComplexity", %{"L" => "LOW", "H" => "HIGH"}},
    {"AT", "attackRequirements", %{"N" => "NONE", "P" => "PRESENT"}},
    {"PR", "privilegesRequired", %{"N" => "NONE", "L" => "LOW", "H" => "HIGH"}},
    {"UI", "userInteraction", %{"N" => "NONE", "P" => "PASSIVE", "A" => "ACTIVE"}},
    {"VC", "vulnConfidentialityImpact", %{"H" => "HIGH", "L" => "LOW", "N" => "NONE"}},
    {"VI", "vulnIntegrityImpact", %{"H" => "HIGH", "L" => "LOW", "N" => "NONE"}},
    {"VA", "vulnAvailabilityImpact", %{"H" => "HIGH", "L" => "LOW", "N" => "NONE"}},
    {"SC", "subConfidentialityImpact", %{"H" => "HIGH", "L" => "LOW", "N" => "NONE"}},
    {"SI", "subIntegrityImpact", %{"H" => "HIGH", "L" => "LOW", "N" => "NONE"}},
    {"SA", "subAvailabilityImpact", %{"H" => "HIGH", "L" => "LOW", "N" => "NONE"}}
  ]

  @supplemental [
    {"S", "Safety", %{"X" => "NOT_DEFINED", "N" => "NEGLIGIBLE", "P" => "PRESENT"}},
    {"AU", "Automatable", %{"X" => "NOT_DEFINED", "N" => "NO", "Y" => "YES"}},
    {"R", "Recovery", %{"X" => "NOT_DEFINED", "A" => "AUTOMATIC", "U" => "USER", "I" => "IRRECOVERABLE"}},
    {"V", "valueDensity", %{"X" => "NOT_DEFINED", "D" => "DIFFUSE", "C" => "CONCENTRATED"}},
    {"RE", "vulnerabilityResponseEffort", %{"X" => "NOT_DEFINED", "L" => "LOW", "M" => "MODERATE", "H" => "HIGH"}},
    {"U", "providerUrgency",
     %{
       "X" => "NOT_DEFINED",
       "Clear" => "CLEAR",
       "Green" => "GREEN",
       "Amber" => "AMBER",
       "Red" => "RED"
     }}
  ]

  @optional [
    {"E", "exploitMaturity", %{"X" => "NOT_DEFINED", "A" => "ATTACKED", "P" => "PROOF_OF_CONCEPT", "U" => "UNREPORTED"}},
    {"CR", "confidentialityRequirement", %{"X" => "NOT_DEFINED", "H" => "HIGH", "M" => "MEDIUM", "L" => "LOW"}},
    {"IR", "integrityRequirement", %{"X" => "NOT_DEFINED", "H" => "HIGH", "M" => "MEDIUM", "L" => "LOW"}},
    {"AR", "availabilityRequirement", %{"X" => "NOT_DEFINED", "H" => "HIGH", "M" => "MEDIUM", "L" => "LOW"}},
    {"MAV", "modifiedAttackVector",
     %{
       "X" => "NOT_DEFINED",
       "N" => "NETWORK",
       "A" => "ADJACENT",
       "L" => "LOCAL",
       "P" => "PHYSICAL"
     }},
    {"MAC", "modifiedAttackComplexity", %{"X" => "NOT_DEFINED", "L" => "LOW", "H" => "HIGH"}},
    {"MAT", "modifiedAttackRequirements", %{"X" => "NOT_DEFINED", "N" => "NONE", "P" => "PRESENT"}},
    {"MPR", "modifiedPrivilegesRequired", %{"X" => "NOT_DEFINED", "N" => "NONE", "L" => "LOW", "H" => "HIGH"}},
    {"MUI", "modifiedUserInteraction", %{"X" => "NOT_DEFINED", "N" => "NONE", "P" => "PASSIVE", "A" => "ACTIVE"}},
    {"MVC", "modifiedVulnConfidentialityImpact", %{"X" => "NOT_DEFINED", "H" => "HIGH", "L" => "LOW", "N" => "NONE"}},
    {"MVI", "modifiedVulnIntegrityImpact", %{"X" => "NOT_DEFINED", "H" => "HIGH", "L" => "LOW", "N" => "NONE"}},
    {"MVA", "modifiedVulnAvailabilityImpact", %{"X" => "NOT_DEFINED", "H" => "HIGH", "L" => "LOW", "N" => "NONE"}},
    {"MSC", "modifiedSubConfidentialityImpact",
     %{"X" => "NOT_DEFINED", "H" => "HIGH", "L" => "LOW", "N" => "NEGLIGIBLE"}},
    {"MSI", "modifiedSubIntegrityImpact",
     %{"X" => "NOT_DEFINED", "H" => "HIGH", "L" => "LOW", "N" => "NEGLIGIBLE", "S" => "SAFETY"}},
    {"MSA", "modifiedSubAvailabilityImpact",
     %{"X" => "NOT_DEFINED", "H" => "HIGH", "L" => "LOW", "N" => "NEGLIGIBLE", "S" => "SAFETY"}}
  ]

  @doc "The full cvssV4_0 metric object for a parsed CVSS v4 vector."
  @spec expand(CVSS.t()) :: map()
  def expand(%CVSS{version: :v4} = cvss) do
    metrics = parse_vector(cvss.vector)

    %{
      "version" => "4.0",
      "vectorString" => cvss.vector,
      "baseScore" => cvss.score,
      "baseSeverity" => cvss.severity |> to_string() |> String.upcase()
    }
    |> put_metrics(@base, metrics, :require)
    |> put_metrics(@supplemental, metrics, {:default, "X"})
    |> put_metrics(@optional, metrics, :when_present)
  end

  defp parse_vector("CVSS:4.0/" <> rest) do
    rest
    |> String.split("/")
    |> Map.new(fn part ->
      [code, value] = String.split(part, ":", parts: 2)
      {code, value}
    end)
  end

  defp put_metrics(object, table, metrics, mode) do
    Enum.reduce(table, object, fn {code, field, values}, acc ->
      case {Map.fetch(metrics, code), mode} do
        {{:ok, code_value}, _mode} -> Map.put(acc, field, Map.fetch!(values, code_value))
        {:error, {:default, default}} -> Map.put(acc, field, Map.fetch!(values, default))
        {:error, :when_present} -> acc
        {:error, :require} -> raise ArgumentError, "CVSS v4 vector is missing base metric #{code}"
      end
    end)
  end
end
