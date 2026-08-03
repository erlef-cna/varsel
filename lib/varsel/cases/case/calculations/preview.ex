# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.Preview do
  @moduledoc """
  Renders a case into a `Result` (the full CVE 5.2 record plus review/publish
  metadata) without publishing.

  Loading this calculation is the only preview entry point, so authorization is
  the case read policy itself — you can only `load(:preview)` on a case you were
  allowed to read.

  Rendering is pure with respect to derivation: it reads each affected package's
  cached derivation (`derivation_cache`), so callers recompute derivations first
  when fresh ranges are needed (`refresh_derivation`). Escape hatches apply
  innermost-out: channel `versions_override` → channel `entry_override` → case
  `cna_override` (all RFC 7396 map patches); the result reports which fired and
  which conditions block publishing.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation
  alias Ash.Resource.Info
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case.Calculations.Preview.Channel
  alias Varsel.Cases.Case.Calculations.Preview.CvssV4
  alias Varsel.Cases.Case.Calculations.Preview.MergePatch
  alias Varsel.Cases.Case.Calculations.Preview.Result
  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseCredit.CreditType
  alias Varsel.Cases.CaseImpact
  alias Varsel.Cases.CaseReference
  alias Varsel.Cases.CaseWeakness
  alias Varsel.Cases.DerivationFreshness
  alias Varsel.Cases.Description.AffectedSummary
  alias Varsel.Cases.Markdown
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.VersionEvent

  # The relationship tree the render reads. Calculation loads are strict — a
  # nested relationship only materializes the fields you name — so each is
  # loaded with all of its attributes (`all_fields/1`), and the catalog
  # relationships spell out the `:name` the render reads.
  @impl Calculation
  def load(_query, _opts, _context) do
    [
      :cve_id,
      references: all_fields(CaseReference),
      credits: all_fields(CaseCredit),
      weaknesses: all_fields(CaseWeakness) ++ [weakness: [:name]],
      impacts: all_fields(CaseImpact) ++ [attack_pattern: [:name]],
      affected_packages:
        all_fields(AffectedPackage) ++
          [channels: all_fields(PackageChannel), version_events: all_fields(VersionEvent)]
    ]
  end

  defp all_fields(resource), do: Enum.map(Info.attributes(resource), & &1.name)

  @impl Calculation
  def calculate(records, _opts, _context), do: Enum.map(records, &render/1)

  # Placeholder `cveMetadata.cveId` before a real ID is assigned, so the preview
  # can still assemble a complete, validatable record. The publish path guards
  # on an assigned CVE record first (see PublishToCveRecord), so a placeholder
  # never reaches a real MITRE push.
  @placeholder_cve_id "CVE-0000-0000"

  defp render(case_record) do
    derivations = derivations(case_record)
    {affected, affected_overrides, affected_blockers} = affected(case_record, derivations)

    cna =
      %{"providerMetadata" => provider_metadata()}
      |> put_present("title", case_record.title)
      |> put_prose("descriptions", description_markdown(case_record.description_md, affected))
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
      cve_record: cve_record(case_record, cna),
      overrides_applied: affected_overrides ++ cna_override_applied,
      # Derivation-level problems: pending fixes and git/channel issues.
      blockers: affected_blockers
    }
  end

  # Cached derivation per affected package, keyed by id. A nil or stale cache
  # renders as empty ranges; the staleness/missing-versions blockers in
  # package_blockers/2 (via DerivationFreshness) catch that silent emptiness.
  defp derivations(case_record) do
    Map.new(case_record.affected_packages, fn package ->
      {package.id, package.derivation_cache || %{}}
    end)
  end

  # Wraps the CNA container into the full CVE 5.2 record.
  defp cve_record(case_record, cna) do
    %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => case_record.cve_id || @placeholder_cve_id,
        "assignerOrgId" => Application.fetch_env!(:varsel, :cna_org_id),
        "assignerShortName" => Application.get_env(:varsel, :cna_short_name, "EEF"),
        "state" => "PUBLISHED"
      },
      "containers" => %{"cna" => cna}
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

  # The description alone among the prose fields gains a derived tail: the
  # "This issue affects …" sentence, built from the very `affected[]` this
  # record publishes so the two can never disagree. Authors never write it —
  # see `Varsel.Cases.Case`'s `description_md`.
  #
  # It is appended as markdown and handed to `put_prose/3`, so every
  # representation renders through the same path as any other prose field: the
  # renderer turns the sentence's U+00A0 into `&nbsp;` for the HTML value and
  # leaves it a bare codepoint elsewhere.
  defp description_markdown(authored, affected) do
    [authored, AffectedSummary.summarize(affected)]
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.join("\n\n")
    |> case do
      "" -> nil
      markdown -> markdown
    end
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
  # With no stored `vendor-advisory`, our own page becomes the advisory of
  # record and is tagged `third-party-advisory`.
  defp references(case_record) do
    stored =
      case_record.references
      |> Enum.sort_by(& &1.position)
      |> Enum.map(fn reference -> render_reference(reference.url, reference.tags) end)

    {advisory, rest} = Enum.split(stored, 1)

    Enum.uniq_by(
      advisory ++ self_links(case_record.cve_id, stored) ++ rest ++ patch_links(case_record),
      & &1["url"]
    )
  end

  defp render_reference(url, []), do: %{"url" => url}
  defp render_reference(url, tags), do: %{"tags" => tags, "url" => url}

  defp self_links(nil, _stored), do: []

  defp self_links(cve_id, stored) do
    website = Application.get_env(:varsel, :cna_website_base_url, "https://cna.erlef.org")

    [
      %{"tags" => self_tags(stored), "url" => "#{website}/cves/#{cve_id}.html"},
      %{"tags" => ["related"], "url" => "https://osv.dev/vulnerability/EEF-#{cve_id}"}
    ]
  end

  # Without a vendor advisory among the stored references our own CVE page is
  # the advisory of record, so it carries `third-party-advisory` (we are not the
  # vendor) on top of `related`.
  defp self_tags(stored) do
    if Enum.any?(stored, &("vendor-advisory" in Map.get(&1, "tags", []))) do
      ["related"]
    else
      ["related", "third-party-advisory"]
    end
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

            {entry, Enum.map(applied, &"#{package.product}/#{channel.purl_type}: #{&1}")}
          end)
          |> Enum.unzip()

        # The implicit git/forge entry closes the package's entries, matching
        # the published convention (registry entries first, github last).
        git_entry = Channel.render_git(package, derivation["git"])
        package_entries = package_entries ++ List.wrap(git_entry)

        {entries ++ package_entries, overrides ++ List.flatten(package_overrides),
         blockers ++ package_blockers(package, derivation)}
      end)

    {entries, overrides, blockers}
  end

  defp package_blockers(package, derivation) do
    issues =
      freshness_blockers(package) ++
        Enum.map(derivation["issues"] || [], &"#{package.product}: #{&1}")

    git_issues =
      for issue <- (derivation["git"] || %{})["issues"] || [] do
        "#{package.product}/git: #{issue}"
      end

    channel_issues =
      for {channel, result} <- overridable_channel_results(package, derivation),
          issue <- result["issues"] || [] do
        "#{package.product}/#{channel.purl_type}: #{issue}"
      end

    issues ++
      git_issues ++
      channel_issues ++
      call_out_blockers(package, derivation) ++
      Enum.uniq(pending_blockers(package, derivation))
  end

  # Reachability call-outs (e.g. a pre-release whose affected status contradicts
  # the surrounding releases) need a human to confirm before publishing. The
  # cache is jsonb, so keys come back as strings.
  defp call_out_blockers(package, derivation) do
    for call_out <- derivation["call_outs"] || [] do
      "#{package.product}: #{call_out["reason"]} at #{call_out["version"]} — review before publishing"
    end
  end

  # A stale cache renders old/empty ranges; a fresh-but-empty derivation renders
  # an affected entry with no versions. Both are silently wrong, so both block.
  defp freshness_blockers(package) do
    cond do
      DerivationFreshness.stale?(package) ->
        [
          "#{package.product}: version derivation is out of date — " <>
            "run refresh_derivation before publishing"
        ]

      DerivationFreshness.missing_versions?(package) ->
        ["#{package.product}: has boundary facts but derived no affected versions"]

      true ->
        []
    end
  end

  defp pending_blockers(%{allow_unreleased_fix: true}, _derivation), do: []

  defp pending_blockers(package, derivation) do
    for {channel, result} <- overridable_channel_results(package, derivation),
        sha <- result["pending"] || [] do
      "#{package.product}/#{channel.purl_type}: fix #{sha} has no containing release yet " <>
        "(set allow_unreleased_fix or a versions_override to publish anyway)"
    end
  end

  # Channel results whose escape hatch is not set — only those can block.
  defp overridable_channel_results(package, derivation) do
    for {channel_id, result} <- derivation["channels"] || %{},
        channel = Enum.find(package.channels, &(&1.id == channel_id)),
        channel.versions_override == nil do
      {channel, result}
    end
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
