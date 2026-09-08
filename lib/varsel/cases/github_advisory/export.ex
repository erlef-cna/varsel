# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Export do
  @moduledoc """
  Writes a case the way GitHub's advisory requests want it: the fields of an
  update or a private report, from a case loaded as `load/0` says.

  ## What travels

    * `title` as `summary`, the assigned CVE ID as `cve_id`, `cvss_v4` as
      `cvss_vector_string`, CWEs as `cwe_ids`, and `description/1` as
      `description`.
    * Credits as `login` and `type`, one per person. GitHub knows people by
      login and gives each person one role. The advisory's own role stands
      for a person it already credits. A person new to it gets the
      weightiest of their roles here
      (`Varsel.Cases.CaseCredit.CreditType.weightiest/1`). A person without
      a linked GitHub account cannot be stated and is reported back as
      skipped. A push never drops a credit.
    * Affected packages as `vulnerabilities`, one per derived range of each
      channel, spelled as `Varsel.Cases.Derivation.Emit.github/3` cached
      them. A `pkg:hex` channel is an `erlang` package. Every other channel
      is `other`, named as the channel is. An advisory entry that names a
      channel with derived ranges (`Varsel.Cases.GitHubAdvisory.Channels`)
      is replaced by them, in its place. Every other advisory entry stays as
      it is. A push never drops an entry.
  """

  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseCredit.CreditType
  alias Varsel.Cases.GitHubAdvisory.Channels
  alias Varsel.Cases.GitHubAdvisory.Import
  alias Varsel.Cases.GitHubAdvisory.People
  alias Varsel.CVE.Advisory

  @type field :: :title | :description | :cve_id | :cvss_v4 | :weaknesses | :credits | :affected

  @type t :: %{body: %{String.t() => term()}, skipped_credits: [String.t()]}

  @doc "What a case has to have loaded for `body/3`, `description/1` and the diff."
  @spec load() :: keyword()
  def load do
    [
      :cve_id,
      :preview,
      weaknesses: [:cwe_id],
      credits: [:name, :credit_type, :handles],
      affected_packages: [
        :product,
        :derivation_cache,
        channels: [:purl_type, :name, :kind, :domain]
      ]
    ]
  end

  @doc """
  The request fields for `fields` of the case. `advisory` is the advisory as
  GitHub last returned it, whose credits and affected entries are kept. nil
  for a report.
  """
  @spec body(Case.t(), [field()], map() | nil) :: t()
  def body(case_record, fields, advisory \\ nil) do
    Enum.reduce(fields, %{body: %{}, skipped_credits: []}, fn field, export ->
      put_field(export, field, case_record, advisory)
    end)
  end

  @doc """
  The case as one advisory document, every section of `Varsel.CVE.Advisory`
  with the references, rendered off the preview. GitHub's own descriptions
  head their sections at level 3. nil for a case whose record has no prose
  yet.
  """
  @spec description(Case.t()) :: String.t() | nil
  def description(%{preview: %{cve_record: %{"containers" => %{"cna" => cna}}}}) do
    case Advisory.render(cna, Advisory.keys(), heading_level: 3) do
      "" -> nil
      text -> text
    end
  end

  def description(_case_record), do: nil

  @doc "The vector string of a case CVSS value, or nil."
  @spec vector(term()) :: String.t() | nil
  def vector(%{vector: vector}) when is_binary(vector), do: vector
  def vector(_absent), do: nil

  defp put_field(export, :title, %{title: title}, _advisory), do: put_present(export, "summary", title)

  defp put_field(export, :cve_id, %{cve_id: cve_id}, _advisory), do: put_present(export, "cve_id", cve_id)

  defp put_field(export, :description, case_record, _advisory) do
    put_present(export, "description", description(case_record))
  end

  defp put_field(export, :cvss_v4, %{cvss_v4: cvss}, _advisory) do
    put_present(export, "cvss_vector_string", vector(cvss))
  end

  defp put_field(export, :weaknesses, %{weaknesses: weaknesses}, _advisory) do
    put_body(export, "cwe_ids", Enum.map(weaknesses, &"CWE-#{&1.cwe_id}"))
  end

  defp put_field(export, :credits, %{credits: credits}, advisory) do
    {on_github, skipped} = credits |> People.people() |> Enum.split_with(&is_binary(&1.login))
    existing = existing_credits(advisory)
    known = MapSet.new(existing, &String.downcase(&1["login"]))

    added =
      for person <- on_github, not MapSet.member?(known, person.login) do
        %{
          "login" => person.login,
          "type" => person.roles |> CreditType.weightiest() |> to_string()
        }
      end

    export
    |> put_body("credits", existing ++ added)
    |> Map.update!(:skipped_credits, &(&1 ++ Enum.map(skipped, fn person -> person.name end)))
  end

  defp put_field(export, :affected, case_record, advisory) do
    put_body(export, "vulnerabilities", vulnerabilities(case_record, advisory))
  end

  defp put_body(export, key, value), do: %{export | body: Map.put(export.body, key, value)}

  defp put_present(export, _key, nil), do: export
  defp put_present(export, key, value), do: put_body(export, key, value)

  defp existing_credits(nil), do: []

  defp existing_credits(advisory) do
    for %{"login" => login, "type" => type} <- List.wrap(advisory["credits"]), is_binary(login) do
      %{"login" => login, "type" => type}
    end
  end

  defp vulnerabilities(case_record, advisory) do
    channels = Channels.of_case(case_record)
    preset = advisory && Import.preset(advisory)
    named = Map.new(advisory_vulnerabilities(advisory), &{&1.position, &1})

    {entries, written} =
      advisory
      |> advisory_entries()
      |> Enum.with_index()
      |> Enum.flat_map_reduce(MapSet.new(), fn {entry, index}, written ->
        replace(entry, channel_for(named[index], channels, preset), written)
      end)

    entries ++
      for channel <- channels,
          not MapSet.member?(written, channel.id),
          entry <- channel_entries(channel),
          do: entry
  end

  defp channel_for(nil, _channels, _preset), do: nil

  defp channel_for(vulnerability, channels, preset) do
    Enum.find(channels, &Channels.matches?(&1, vulnerability, preset))
  end

  defp replace(_entry, %{github_ranges: [_range | _rest], id: id} = channel, written) do
    if MapSet.member?(written, id),
      do: {[], written},
      else: {channel_entries(channel), MapSet.put(written, id)}
  end

  defp replace(entry, _channel, written), do: {[entry], written}

  defp advisory_entries(nil), do: []
  defp advisory_entries(advisory), do: List.wrap(advisory["vulnerabilities"])

  defp advisory_vulnerabilities(nil), do: []
  defp advisory_vulnerabilities(advisory), do: Import.vulnerabilities(advisory)

  defp channel_entries(channel) do
    for range <- channel.github_ranges do
      %{
        "package" => %{
          "ecosystem" => ecosystem(channel),
          "name" => channel.name || channel.product
        },
        "vulnerable_version_range" => range["vulnerable_version_range"],
        "patched_versions" => Enum.join(range["patched_versions"] || [], ", ")
      }
    end
  end

  defp ecosystem(%{purl_type: "hex"}), do: "erlang"
  defp ecosystem(_channel), do: "other"
end
