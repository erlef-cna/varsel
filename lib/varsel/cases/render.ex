# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Render do
  @moduledoc """
  Assembles a case into a CVE JSON 5.2 CNA container.

  Pure with respect to derivation: version data comes in as the per-package
  derivation results (`Varsel.Cases.Derivation.derive/1`), so rendering never
  performs I/O and is fully testable. The publish pipeline recomputes
  derivations first; previews may use the cached ones.

  Escape hatches apply innermost-out: channel `versions_override` →
  channel `entry_override` → case `cna_override` (all RFC 7396 for the map
  patches). The result reports which hatches fired and which conditions
  block publishing.
  """

  alias Varsel.Cases.CaseCredit.CreditType
  alias Varsel.Cases.Markdown
  alias Varsel.Cases.Render.Channel
  alias Varsel.Cases.Render.CvssV4
  alias Varsel.Cases.Render.MergePatch

  defmodule Result do
    @moduledoc "Outcome of rendering a case: the container plus review/publish metadata."

    @enforce_keys [:cna, :overrides_applied, :blockers]
    defstruct [:cna, :overrides_applied, :blockers]

    @type t :: %__MODULE__{
            cna: map(),
            overrides_applied: [String.t()],
            blockers: [String.t()]
          }
  end

  @doc """
  Renders the CNA container for a case.

  The case must have loaded: `cve_id`, `references`, `credits`,
  `weaknesses.weakness`, `impacts.attack_pattern`, and
  `affected_packages.channels`. `derivations` maps affected-package ids to
  their derivation results.
  """
  @spec render_cna(Varsel.Cases.Case.t(), %{Ash.UUID.t() => map()}) :: Result.t()
  def render_cna(case_record, derivations) do
    {affected, affected_overrides, affected_blockers} = affected(case_record, derivations)

    cna =
      %{"providerMetadata" => provider_metadata()}
      |> put_present("title", case_record.title)
      |> put_prose("descriptions", case_record.description_md)
      |> put_prose("workarounds", case_record.workarounds_md)
      |> put_prose("configurations", case_record.configurations_md)
      |> put_prose("solutions", case_record.solutions_md)
      |> Map.put("source", %{
        "discovery" => case_record.discovery |> to_string() |> String.upcase()
      })
      |> put_present("datePublic", format_time(case_record.date_public))
      |> put_timeline(case_record.timeline)
      |> put_metrics(case_record.cvss_v4)
      |> put_problem_types(case_record.weaknesses)
      |> put_impacts(case_record.impacts)
      |> put_credits(case_record.credits)
      |> Map.put("references", references(case_record))
      |> put_non_empty("affected", affected)
      |> put_cpe_applicability(case_record, derivations)

    {cna, cna_override_applied} =
      case case_record.cna_override do
        nil -> {cna, []}
        override -> {MergePatch.apply(cna, override), ["cna_override"]}
      end

    %Result{
      cna: cna,
      overrides_applied: affected_overrides ++ cna_override_applied,
      blockers: blockers(case_record, affected_blockers)
    }
  end

  ## ------------------------------------------------------------------ prose

  # Every markdown-backed section ships three representations: the plain-text
  # `value` (required by the schema), the rendered HTML, and the markdown
  # source itself — so consumers (and future amendments) get the authored
  # text back verbatim. Timeline entries stay plain-text only: the schema
  # gives timeline[] no supportingMedia.
  defp put_prose(cna, _key, nil), do: cna

  defp put_prose(cna, key, markdown) do
    markdown = String.trim(markdown)

    Map.put(cna, key, [
      %{
        "lang" => "en",
        "value" => Markdown.to_plaintext(markdown),
        "supportingMedia" => [
          %{"base64" => false, "type" => "text/html", "value" => Markdown.to_html(markdown)},
          %{"base64" => false, "type" => "text/markdown", "value" => markdown}
        ]
      }
    ])
  end

  defp put_timeline(cna, []), do: cna

  defp put_timeline(cna, timeline) do
    entries =
      timeline
      |> Enum.sort_by(& &1.time, DateTime)
      |> Enum.map(fn entry ->
        %{
          "lang" => "en",
          "time" => format_time(entry.time),
          "value" => Markdown.to_plaintext(entry.value_md)
        }
      end)

    Map.put(cna, "timeline", entries)
  end

  ## ------------------------------------------------------- classifications

  defp put_metrics(cna, nil), do: cna

  defp put_metrics(cna, cvss) do
    Map.put(cna, "metrics", [
      %{
        "format" => "CVSS",
        "scenarios" => [%{"lang" => "en", "value" => "GENERAL"}],
        "cvssV4_0" => CvssV4.expand(cvss)
      }
    ])
  end

  defp put_problem_types(cna, []), do: cna

  defp put_problem_types(cna, weaknesses) do
    problem_types =
      weaknesses
      |> Enum.sort_by(& &1.position)
      |> Enum.map(fn case_weakness ->
        cwe = "CWE-#{case_weakness.cwe_id}"

        %{
          "descriptions" => [
            %{
              "cweId" => cwe,
              "description" => "#{cwe} #{case_weakness.weakness.name}",
              "lang" => "en",
              "type" => "CWE"
            }
          ]
        }
      end)

    Map.put(cna, "problemTypes", problem_types)
  end

  defp put_impacts(cna, []), do: cna

  defp put_impacts(cna, impacts) do
    rendered =
      impacts
      |> Enum.sort_by(& &1.position)
      |> Enum.map(fn case_impact ->
        capec = "CAPEC-#{case_impact.capec_id}"

        %{
          "capecId" => capec,
          "descriptions" => [
            %{"lang" => "en", "value" => "#{capec} #{case_impact.attack_pattern.name}"}
          ]
        }
      end)

    Map.put(cna, "impacts", rendered)
  end

  defp put_credits(cna, []), do: cna

  defp put_credits(cna, credits) do
    rendered =
      credits
      |> Enum.sort_by(& &1.position)
      |> Enum.map(fn credit ->
        value =
          case credit.organization do
            nil -> credit.name
            organization -> "#{credit.name} / #{organization}"
          end

        %{
          "lang" => "en",
          "type" => CreditType.render(credit.credit_type),
          "value" => value
        }
      end)

    Map.put(cna, "credits", rendered)
  end

  ## ------------------------------------------------------------- references

  # Stored references (ordered) with the derived self-links spliced in after
  # the leading vendor advisory and derived fix-commit links appended last —
  # the published convention: advisory, cna.erlef.org, osv.dev, stored
  # patches/extras, fix commits. Stored rows win over derived on URL conflict.
  defp references(case_record) do
    stored =
      case_record.references
      |> Enum.sort_by(& &1.position)
      |> Enum.map(fn reference -> render_reference(reference.url, reference.tags) end)

    {advisory, rest} = Enum.split(stored, 1)

    Enum.uniq_by(
      advisory ++ self_links(case_record.cve_id) ++ rest ++ patch_links(case_record),
      & &1["url"]
    )
  end

  defp render_reference(url, []), do: %{"url" => url}
  defp render_reference(url, tags), do: %{"tags" => tags, "url" => url}

  defp self_links(nil), do: []

  defp self_links(cve_id) do
    website = Application.get_env(:varsel, :cna_website_base_url, "https://cna.erlef.org")

    [
      %{"tags" => ["related"], "url" => "#{website}/cves/#{cve_id}.html"},
      %{"tags" => ["related"], "url" => "https://osv.dev/vulnerability/EEF-#{cve_id}"}
    ]
  end

  defp patch_links(case_record) do
    for package <- case_record.affected_packages,
        package.repo_url,
        event <- package.version_events,
        event.event == :fixed,
        event.commit_sha do
      %{"tags" => ["patch"], "url" => "#{package.repo_url}/commit/#{event.commit_sha}"}
    end
  end

  ## --------------------------------------------------------------- affected

  defp affected(case_record, derivations) do
    {entries, overrides, blockers} =
      case_record.affected_packages
      |> Enum.sort_by(& &1.position)
      |> Enum.reduce({[], [], []}, fn package, {entries, overrides, blockers} ->
        derivation = derivations[package.id] || %{}
        channel_results = derivation["channels"] || %{}

        {package_entries, package_overrides} =
          package.channels
          |> Enum.sort_by(& &1.position)
          |> Enum.map(fn channel ->
            {entry, applied} =
              Channel.render(package, channel, channel_results[channel.id] || %{})

            {entry, Enum.map(applied, &"#{package.product}/#{channel.channel_type}: #{&1}")}
          end)
          |> Enum.unzip()

        {entries ++ package_entries, overrides ++ List.flatten(package_overrides),
         blockers ++ package_blockers(package, derivation)}
      end)

    {entries, overrides, blockers}
  end

  defp package_blockers(package, derivation) do
    issues = Enum.map(derivation["issues"] || [], &"#{package.product}: #{&1}")

    channel_issues =
      for {channel_id, result} <- derivation["channels"] || %{},
          channel = Enum.find(package.channels, &(&1.id == channel_id)),
          channel.versions_override == nil,
          issue <- result["issues"] || [] do
        "#{package.product}/#{channel.channel_type}: #{issue}"
      end

    pending =
      if package.allow_unreleased_fix do
        []
      else
        for {channel_id, result} <- derivation["channels"] || %{},
            channel = Enum.find(package.channels, &(&1.id == channel_id)),
            channel.channel_type != :git,
            channel.versions_override == nil,
            sha <- result["pending"] || [] do
          "#{package.product}/#{channel.channel_type}: fix #{sha} has no containing release yet " <>
            "(set allow_unreleased_fix or a versions_override to publish anyway)"
        end
      end

    issues ++ channel_issues ++ Enum.uniq(pending)
  end

  defp put_cpe_applicability(cna, case_record, derivations) do
    matches =
      for package <- Enum.sort_by(case_record.affected_packages, & &1.position),
          match <- (derivations[package.id] || %{})["cpe_matches"] || [] do
        %{"criteria" => Channel.cpe(package), "vulnerable" => true}
        |> put_present("versionStartIncluding", match["versionStartIncluding"])
        |> put_present("versionEndExcluding", match["versionEndExcluding"])
      end

    case matches do
      [] ->
        cna

      matches ->
        Map.put(cna, "cpeApplicability", [
          %{
            "nodes" => [%{"cpeMatch" => matches, "negate" => false, "operator" => "OR"}],
            "operator" => "AND"
          }
        ])
    end
  end

  ## --------------------------------------------------------------- blockers

  defp blockers(case_record, affected_blockers) do
    checks = [
      {case_record.title == nil, "title is missing"},
      {case_record.description_md == nil, "description is missing"},
      {case_record.cvss_v4 == nil, "CVSS v4 vector is missing"},
      {case_record.affected_packages == [], "no affected packages recorded"},
      {case_record.references == [], "no references recorded (the vendor advisory comes first)"},
      {case_record.cve_id == nil, "no CVE ID assigned"}
    ]

    for({true, message} <- checks, do: message) ++ affected_blockers
  end

  ## ---------------------------------------------------------------- helpers

  defp provider_metadata do
    %{
      "orgId" => Application.fetch_env!(:varsel, :cna_org_id),
      "shortName" => Application.get_env(:varsel, :cna_short_name, "EEF")
    }
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  defp put_non_empty(map, _key, []), do: map
  defp put_non_empty(map, key, value), do: Map.put(map, key, value)

  defp format_time(nil), do: nil
  defp format_time(%DateTime{} = time), do: DateTime.to_iso8601(time)
end
