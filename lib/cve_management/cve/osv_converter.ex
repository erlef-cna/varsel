# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.OsvConverter do
  @moduledoc """
  Converts CVE records (CVE JSON 5.x) into OSV documents.

  Port of the former `cve-to-osv` script from the manual CNA workflow. The
  conversion itself is pure — the returned document contains no `modified`
  timestamp and no enumerated hex package versions. Both are owned by
  `CveManagement.CVE.OsvRecord`: the `modified` timestamp advances only
  when the derived content changes, and hex.pm version enumeration requires
  network access (see `enumerate_affected_versions/2`).

  A CVE record is convertible when it is `PUBLISHED` at MITRE and has at
  least one affected entry describing a hex or npm package with semver
  version information or a git repository with commit version information.
  """

  @schema_version "1.7.3"

  # Package registries mirrored to OSV. Only hex packages get their concrete
  # affected versions enumerated (see enumerate_affected_versions/2).
  @registries [
    %{
      ecosystem: "Hex",
      purl_type: "hex",
      collection_url: "https://repo.hex.pm",
      package_site: "https://hex.pm/packages/"
    },
    %{
      ecosystem: "npm",
      purl_type: "npm",
      collection_url: "https://registry.npmjs.org",
      package_site: "https://www.npmjs.com/package/"
    }
  ]

  @credit_types %{
    "finder" => "FINDER",
    "reporter" => "REPORTER",
    "analyst" => "ANALYST",
    "coordinator" => "COORDINATOR",
    "remediation developer" => "REMEDIATION_DEVELOPER",
    "remediation reviewer" => "REMEDIATION_REVIEWER",
    "remediation verifier" => "REMEDIATION_VERIFIER",
    "tool" => "TOOL",
    "sponsor" => "SPONSOR",
    "other" => "OTHER"
  }

  @event_order %{"introduced" => 1, "fixed" => 2, "last_affected" => 3, "limit" => 4}

  @doc """
  Converts a CVE record into an OSV document.

  Returns `{:ok, osv}` — without `modified` and without enumerated hex
  `versions` — or `{:skip, reason}` when the record has no OSV
  representation.
  """
  @spec convert(map()) :: {:ok, map()} | {:skip, String.t()}
  def convert(cve_json) when is_map(cve_json) do
    case convertible(cve_json) do
      :ok -> {:ok, do_convert(cve_json)}
      {:skip, reason} -> {:skip, reason}
    end
  end

  defp convertible(cve_json) do
    affected = get_in(cve_json, ["containers", "cna", "affected"]) || []

    cond do
      get_in(cve_json, ["cveMetadata", "state"]) != "PUBLISHED" ->
        {:skip, "CVE record is not published at MITRE"}

      is_nil(get_in(cve_json, ["cveMetadata", "datePublished"])) ->
        {:skip, "datePublished is not set"}

      not Enum.any?(affected, &(registry_affected?(&1) or git_affected?(&1))) ->
        {:skip, "No hex, npm, or git repositories with appropriate version types found"}

      true ->
        :ok
    end
  end

  defp do_convert(cve_json) do
    cve_id = get_in(cve_json, ["cveMetadata", "cveId"])
    cna = get_in(cve_json, ["containers", "cna"]) || %{}
    references = convert_references(cna)

    %{
      "schema_version" => @schema_version,
      "id" => "EEF-#{cve_id}",
      "published" => format_timestamp(get_in(cve_json, ["cveMetadata", "datePublished"])),
      "aliases" => add_github_advisory_alias([cve_id], references),
      "upstream" => [],
      "related" => [],
      "summary" => extract_summary(cna),
      "details" => extract_details(cna),
      "severity" => convert_severity(cna),
      "affected" => convert_affected(cna),
      "references" => references,
      "credits" => convert_credits(cna),
      "database_specific" => convert_database_specific(cna)
    }
  end

  ## Affected entry classification

  # Package name of an affected entry for the given registry, or nil when
  # the entry does not describe a package of that registry. Old-style
  # records carry collectionURL + packageName; newer records may only carry
  # a pkg:hex/... or pkg:npm/... package URL.
  defp registry_package_name(item, registry) do
    cond do
      item["collectionURL"] == registry.collection_url and is_binary(item["packageName"]) ->
        item["packageName"]

      is_binary(item["packageURL"]) and
          String.starts_with?(item["packageURL"], "pkg:#{registry.purl_type}/") ->
        case Purl.new(item["packageURL"]) do
          {:ok, %Purl{type: type} = purl} when type == registry.purl_type ->
            item["packageName"] || purl_package_name(purl)

          _other ->
            nil
        end

      true ->
        nil
    end
  end

  # Namespaced hex purls (private organization packages) are not published
  # to OSV; npm scopes are part of the public package name.
  defp purl_package_name(%Purl{type: "hex", namespace: [], name: name}), do: name
  defp purl_package_name(%Purl{type: "npm", namespace: [], name: name}), do: name

  defp purl_package_name(%Purl{type: "npm", namespace: [scope], name: name}), do: "#{scope}/#{name}"

  defp purl_package_name(_purl), do: nil

  defp registry_affected?(item), do: Enum.any?(@registries, &registry_affected?(item, &1))

  defp registry_affected?(item, registry),
    do: registry_package_name(item, registry) != nil and version_info?(item, "semver")

  defp git_affected?(item), do: is_binary(item["repo"]) and version_info?(item, "git")

  defp version_info?(item, version_type) do
    versions = item["versions"] || []

    Enum.any?(versions, &(&1["versionType"] == version_type)) or
      (item["defaultStatus"] == "affected" and versions == [])
  end

  ## Summary / details

  defp extract_summary(%{"title" => title}) when is_binary(title), do: title

  defp extract_summary(cna) do
    case english_text(cna["descriptions"]) do
      [description | _] -> description |> String.split("\n") |> List.first() |> String.trim()
      [] -> ""
    end
  end

  defp extract_details(cna) do
    # Only the first English description makes the Summary section; the
    # others are usually auto-generated variants of the same text.
    summary =
      case english_text(cna["descriptions"]) do
        [description | _rest] -> escape_markdown(description)
        [] -> ""
      end

    workarounds = cna["workarounds"] |> english_text() |> escape_and_join()
    configurations = cna["configurations"] |> english_text() |> escape_and_join()

    sections =
      [
        {"Summary", summary},
        {"Workaround", workarounds},
        {"Configuration", configurations}
      ]
      |> Enum.reject(fn {title, text} -> title != "Summary" and text == "" end)
      |> Enum.map(fn {title, text} -> "## #{title}\n\n#{text}" end)

    Enum.join(sections, "\n\n")
  end

  defp english_text(entries) do
    entries
    |> List.wrap()
    |> Enum.filter(&(&1["lang"] == "en"))
    |> Enum.map(&(&1["value"] || ""))
  end

  defp escape_and_join(texts), do: Enum.map_join(texts, "\n\n", &escape_markdown/1)

  defp escape_markdown(text), do: String.replace(text, ~r/([_*\[\]`\\])/, "\\\\\\1")

  ## Affected

  defp convert_affected(cna) do
    affected = cna["affected"] || []

    Enum.flat_map(@registries, &convert_registry_affected(affected, &1)) ++
      convert_git_affected(affected)
  end

  defp convert_registry_affected(affected, registry) do
    affected
    |> Enum.filter(&registry_affected?(&1, registry))
    |> Enum.map(&affected_entry(&1, registry))
  end

  defp affected_entry(item, registry) do
    package_name = registry_package_name(item, registry)

    %{
      "package" => %{
        "ecosystem" => registry.ecosystem,
        "name" => package_name,
        "purl" => package_purl(item, registry, package_name)
      },
      "ranges" => semver_ranges(item)
    }
  end

  defp semver_ranges(item) do
    semver_versions =
      item |> Map.get("versions", []) |> Enum.filter(&(&1["versionType"] == "semver"))

    if semver_versions == [] and item["defaultStatus"] == "affected" do
      # All versions affected
      [%{"type" => "SEMVER", "events" => [%{"introduced" => "0"}]}]
    else
      # Each version entry becomes its own range with its own event set
      Enum.map(semver_versions, &semver_range/1)
    end
  end

  defp semver_range(version_entry) do
    %{
      "type" => "SEMVER",
      "events" => version_entry |> convert_version_events(:semver) |> finalize_events()
    }
  end

  # The OSV package purl: prefer the affected entry's own packageURL as-is,
  # falling back to one built from the package name.
  defp package_purl(item, registry, package_name) do
    with purl_string when is_binary(purl_string) <- item["packageURL"],
         {:ok, %Purl{type: type}} when type == registry.purl_type <- Purl.new(purl_string) do
      purl_string
    else
      _other -> Purl.to_string(build_purl(registry.purl_type, package_name))
    end
  end

  defp build_purl(purl_type, package_name) do
    case String.split(package_name, "/") do
      [name] -> %Purl{type: purl_type, name: name}
      parts -> %Purl{type: purl_type, namespace: Enum.drop(parts, -1), name: List.last(parts)}
    end
  end

  defp convert_git_affected(affected) do
    affected
    |> Enum.filter(&git_affected?/1)
    |> Enum.map(fn item ->
      repo = item["repo"]

      git_versions =
        item |> Map.get("versions", []) |> Enum.filter(&(&1["versionType"] == "git"))

      events =
        if git_versions == [] and item["defaultStatus"] == "affected" do
          [%{"introduced" => "0"}]
        else
          git_versions
          |> Enum.flat_map(&convert_version_events(&1, :git))
          |> Enum.uniq()
          |> finalize_events()
        end

      %{"ranges" => [%{"type" => "GIT", "repo" => repo, "events" => events}]}
    end)
  end

  # Converts one CVE version entry into OSV range events.
  defp convert_version_events(version_entry, type) do
    status = Map.get(version_entry, "status", "affected")

    Enum.uniq(
      base_events(version_entry["version"], status, type) ++
        upper_bound_events(version_entry, status, type) ++ change_events(version_entry, type)
    )
  end

  defp base_events(nil, _status, _type), do: []
  defp base_events("0", "affected", _type), do: [%{"introduced" => "0"}]
  defp base_events("*", _status, _type), do: []
  defp base_events(v, "affected", type), do: [%{"introduced" => clean_version(v, type)}]
  defp base_events(v, "unaffected", type), do: [%{"fixed" => clean_version(v, type)}]
  defp base_events(_v, _status, _type), do: []

  defp upper_bound_events(%{"lessThan" => lt}, "affected", type) when lt not in [nil, "*"],
    do: [%{"fixed" => clean_version(lt, type)}]

  defp upper_bound_events(%{"lessThanOrEqual" => lte}, "affected", type) when lte not in [nil, "*"],
    do: [%{"last_affected" => clean_version(lte, type)}]

  # versions < X are unaffected (unusual but possible)
  defp upper_bound_events(%{"lessThan" => lt}, "unaffected", type) when lt not in [nil, "*"],
    do: [%{"limit" => clean_version(lt, type)}]

  defp upper_bound_events(_version_entry, _status, _type), do: []

  defp change_events(version_entry, type) do
    version_entry
    |> Map.get("changes", [])
    |> Enum.flat_map(&change_event(&1, type))
  end

  defp change_event(%{"status" => "unaffected", "at" => at}, type) when is_binary(at),
    do: [%{"fixed" => clean_version(at, type)}]

  defp change_event(%{"status" => "affected", "at" => at}, :git) when is_binary(at), do: [%{"introduced" => at}]

  defp change_event(_change, _type), do: []

  # Makes a range's event set valid per the OSV schema: every range needs at
  # least one introduced event, and fixed and last_affected are mutually
  # exclusive (fixed, being more precise, wins).
  defp finalize_events(events) do
    events =
      if Enum.any?(events, &Map.has_key?(&1, "introduced")) do
        events
      else
        [%{"introduced" => "0"} | events]
      end

    events =
      if Enum.any?(events, &Map.has_key?(&1, "fixed")) do
        Enum.reject(events, &Map.has_key?(&1, "last_affected"))
      else
        events
      end

    sort_events(events)
  end

  defp clean_version(version, :semver), do: String.replace(version, ~r/^pkg:hex\/[^@]+@/, "")

  defp clean_version(version, :git), do: version

  defp sort_events(events) do
    Enum.sort_by(events, fn event ->
      event |> Map.keys() |> Enum.map(&Map.get(@event_order, &1, 99)) |> Enum.min()
    end)
  end

  ## References

  defp convert_references(cna) do
    base_refs =
      cna
      |> Map.get("references", [])
      |> Enum.reject(&String.contains?(Map.get(&1, "url", ""), "osv.dev"))
      |> Enum.map(fn reference ->
        tags = Map.get(reference, "tags", [])

        type =
          cond do
            "vendor-advisory" in tags -> "ADVISORY"
            "patch" in tags -> "FIX"
            true -> "WEB"
          end

        %{"type" => type, "url" => reference["url"]}
      end)

    package_refs =
      Enum.flat_map(@registries, fn registry ->
        cna
        |> Map.get("affected", [])
        |> Enum.map(&registry_package_name(&1, registry))
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq()
        |> Enum.map(&%{"type" => "PACKAGE", "url" => registry.package_site <> &1})
      end)

    base_refs ++ package_refs
  end

  defp add_github_advisory_alias(aliases, references) do
    case Enum.find_value(references, &ghsa_id/1) do
      nil -> aliases
      ghsa_id -> [ghsa_id | aliases]
    end
  end

  defp ghsa_id(%{"url" => url}) do
    with true <- String.contains?(url, "github.com"),
         true <- String.contains?(url, "advisories/GHSA-"),
         [ghsa_id] <- Regex.run(~r/GHSA-[a-z0-9-]+/, url) do
      ghsa_id
    else
      _ -> nil
    end
  end

  ## Severity / credits / database_specific

  defp convert_severity(cna) do
    cna
    |> Map.get("metrics", [])
    |> Enum.filter(&Map.has_key?(&1, "cvssV4_0"))
    |> Enum.map(&%{"type" => "CVSS_V4", "score" => get_in(&1, ["cvssV4_0", "vectorString"])})
  end

  defp convert_credits(cna) do
    cna
    |> Map.get("credits", [])
    |> Enum.map(
      &%{
        "name" => &1["value"],
        "type" => Map.get(@credit_types, Map.get(&1, "type", ""), "OTHER")
      }
    )
  end

  defp convert_database_specific(cna) do
    cwe_ids =
      cna
      |> Map.get("problemTypes", [])
      |> Enum.flat_map(&Map.get(&1, "descriptions", []))
      |> Enum.map(& &1["cweId"])
      |> Enum.reject(&is_nil/1)

    capec_ids =
      cna
      |> Map.get("impacts", [])
      |> Enum.map(& &1["capecId"])
      |> Enum.reject(&is_nil/1)

    cpe_ids =
      cna
      |> Map.get("affected", [])
      |> Enum.flat_map(&Map.get(&1, "cpes", []))
      |> Enum.uniq()

    %{"cwe_ids" => cwe_ids, "capec_ids" => capec_ids, "cpe_ids" => cpe_ids}
  end

  defp format_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, datetime, _offset} ->
        DateTime.to_iso8601(datetime)

      # The CVE schema allows timestamps without an offset; GMT is assumed.
      # OSV requires RFC3339 with a mandatory offset.
      {:error, :missing_offset} ->
        timestamp
        |> NaiveDateTime.from_iso8601!()
        |> DateTime.from_naive!("Etc/UTC")
        |> DateTime.to_iso8601()
    end
  end

  @doc """
  Hash of an OSV document without its `modified` timestamp — a differing
  hash is exactly the signal that `modified` must advance.
  """
  @spec content_hash(map()) :: String.t()
  def content_hash(osv) do
    :sha256
    |> :crypto.hash(Jason.encode!(Map.delete(osv, "modified")))
    |> Base.encode16(case: :lower)
  end

  ## Version enumeration

  @doc """
  Enumerates the concrete affected hex.pm versions for every hex package
  entry of an OSV document, using `fetch_versions` (a function from package
  name to `{:ok, versions} | {:error, reason}`) to list all released
  versions.

  Returns `{:error, reason}` when any lookup fails — callers should retry
  rather than persist a document with an incomplete version list.
  """
  @spec enumerate_affected_versions(map(), (String.t() -> {:ok, [String.t()]} | {:error, term()})) ::
          {:ok, map()} | {:error, String.t()}
  def enumerate_affected_versions(osv, fetch_versions) do
    osv["affected"]
    |> Enum.reduce_while([], fn
      %{"package" => %{"ecosystem" => "Hex", "name" => name}} = entry, acc ->
        case fetch_versions.(name) do
          {:ok, versions} ->
            affected_versions =
              versions
              |> filter_affected_versions(entry["ranges"])
              |> Enum.uniq()
              |> Enum.sort_by(&Version.parse!/1, Version)

            {:cont, [Map.put(entry, "versions", affected_versions) | acc]}

          {:error, reason} ->
            {:halt, {:error, "Failed to fetch hex.pm versions for #{name}: #{inspect(reason)}"}}
        end

      entry, acc ->
        {:cont, [entry | acc]}
    end)
    |> case do
      {:error, reason} -> {:error, reason}
      entries -> {:ok, Map.put(osv, "affected", Enum.reverse(entries))}
    end
  end

  @doc """
  Filters a list of released versions down to those affected according to
  OSV SEMVER ranges. A version is affected when it satisfies all events of
  any single range.
  """
  @spec filter_affected_versions([String.t()], [map()]) :: [String.t()]
  def filter_affected_versions(versions, ranges) do
    case Enum.filter(ranges, &(&1["type"] == "SEMVER")) do
      [] ->
        # No semver range, include all versions as a safety measure
        versions

      semver_ranges ->
        Enum.filter(versions, fn version ->
          Enum.any?(semver_ranges, &version_in_range?(version, Map.get(&1, "events", [])))
        end)
    end
  end

  defp version_in_range?(version, events) do
    introduced = event_version(events, "introduced")
    fixed = event_version(events, "fixed")
    last_affected = event_version(events, "last_affected")
    limit = event_version(events, "limit")

    after_introduced?(version, introduced) and
      (fixed == nil or Version.compare(version, fixed) == :lt) and
      (last_affected == nil or Version.compare(version, last_affected) != :gt) and
      (limit == nil or Version.compare(version, limit) == :lt)
  end

  defp after_introduced?(_version, nil), do: true
  defp after_introduced?(_version, "0"), do: true
  defp after_introduced?(version, introduced), do: Version.compare(version, introduced) != :lt

  defp event_version(events, event_type), do: Enum.find_value(events, &Map.get(&1, event_type))
end
