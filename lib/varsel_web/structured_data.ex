# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.StructuredData do
  @moduledoc """
  The schema.org JSON-LD documents of the public pages, which search engines
  read for the site's name and logo, the CVE dataset, and each CVE.

  A controller or LiveView assigns one document as `structured_data`, and
  the root layout renders it with `encode/1`.
  """

  use VarselWeb, :verified_routes

  alias VarselWeb.CveLinks
  alias VarselWeb.CveView

  @doc """
  The document as the body of a `<script type="application/ld+json">`.
  `Phoenix.HTML.json_escape/1` writes `<`, `>` and `&` as JSON escapes, so a
  value that holds `</script>` cannot end the element.
  """
  @spec encode(map()) :: Phoenix.HTML.safe()
  def encode(document), do: document |> JSON.encode!() |> Phoenix.HTML.json_escape()

  @doc "The CNA and the site, for the home page."
  @spec home() :: map()
  def home do
    document(%{
      "@graph" => [
        organization(),
        %{
          "@type" => "WebSite",
          "@id" => url(~p"/") <> "#website",
          "name" => "EEF CNA",
          "url" => url(~p"/"),
          "inLanguage" => "en",
          "publisher" => %{"@id" => organization_id()}
        }
      ]
    })
  end

  @doc "The contact page, whose subject is the CNA and how to reach it."
  @spec contact() :: map()
  def contact do
    document(%{
      "@type" => "ContactPage",
      "name" => "Contact the EEF CNA",
      "url" => url(~p"/contact"),
      "mainEntity" =>
        Map.put(organization(), "contactPoint", %{
          "@type" => "ContactPoint",
          "contactType" => "security vulnerability reporting",
          "email" => "cna@erlef.org",
          "url" => url(~p"/report"),
          "availableLanguage" => "English"
        })
    })
  end

  @doc "The published CVEs as a dataset, with its two machine-readable forms."
  @spec cve_catalog() :: map()
  def cve_catalog do
    document(%{
      "@type" => "DataCatalog",
      "@id" => url(~p"/cves"),
      "name" => "EEF CNA CVE records",
      "description" =>
        "The CVE records the Erlang Ecosystem Foundation CNA has published for " <>
          "vulnerabilities in the Erlang, Elixir and BEAM ecosystem.",
      "url" => url(~p"/cves"),
      "publisher" => organization_reference(),
      "dataset" => %{
        "@type" => "Dataset",
        "name" => "EEF CNA CVE records",
        "description" =>
          "Every CVE record the Erlang Ecosystem Foundation CNA has published, in the " <>
            "CVE JSON 5 format, and the same vulnerabilities in the OSV format.",
        "url" => url(~p"/cves"),
        "creator" => organization_reference(),
        "isAccessibleForFree" => true,
        "keywords" => ["CVE", "OSV", "vulnerability", "Erlang", "Elixir", "BEAM", "Hex"],
        "distribution" => [
          %{
            "@type" => "DataDownload",
            "name" => "CVE records",
            "encodingFormat" => "application/json",
            "contentUrl" => url(~p"/cves/index.json")
          },
          %{
            "@type" => "DataDownload",
            "name" => "OSV records",
            "encodingFormat" => "application/json",
            "contentUrl" => url(~p"/osv/all.json")
          }
        ]
      }
    })
  end

  @doc """
  The page of a CVE, from this CNA's `container` in the record. For an
  upstream CVE, the title and summary of the upstream CNA stand in where
  this CNA's container has none.
  """
  @spec cve(map(), map(), map() | nil, [%{href: String.t(), type: String.t()}]) :: map()
  def cve(cve, container, upstream, alternates) do
    meta = cve["cveMetadata"]
    cve_id = meta["cveId"]
    upstream = upstream || %{}

    document(%{
      "@type" => "TechArticle",
      "@id" => CveLinks.html_url(cve_id),
      "url" => CveLinks.html_url(cve_id),
      "identifier" => cve_id,
      "name" => cve_id,
      "headline" => container["title"] || upstream[:title] || cve_id,
      "description" => english_description(container) || upstream[:summary],
      "datePublished" => meta["datePublished"],
      "dateModified" => meta["dateUpdated"],
      "inLanguage" => "en",
      "articleSection" => "Security Advisory",
      "keywords" => keywords(cve_id, container),
      "author" => organization_reference(),
      "publisher" => organization_reference(),
      "sameAs" => "https://www.cve.org/CVERecord?id=#{cve_id}",
      "encoding" =>
        Enum.map(
          alternates,
          &%{
            "@type" => "MediaObject",
            "encodingFormat" => "application/json",
            "contentUrl" => &1.href
          }
        ),
      "about" => Enum.map(List.wrap(container["affected"]), &software/1),
      "contributor" => Enum.map(CveView.credit_roles(List.wrap(container["credits"])), &contributor/1),
      "citation" => Enum.map(VarselWeb.CveHTML.visible_references(container, cve_id), &citation/1)
    })
  end

  defp document(fields) do
    fields
    |> Map.put("@context", "https://schema.org")
    |> compact()
  end

  defp organization do
    %{
      "@type" => "Organization",
      "@id" => organization_id(),
      "name" => "EEF CNA",
      "alternateName" => "Erlang Ecosystem Foundation CVE Numbering Authority",
      "url" => url(~p"/"),
      "email" => "cna@erlef.org",
      "logo" => url(~p"/apple-touch-icon.png"),
      "parentOrganization" => %{
        "@type" => "Organization",
        "name" => "Erlang Ecosystem Foundation",
        "url" => "https://erlef.org"
      }
    }
  end

  defp organization_id, do: url(~p"/") <> "#organization"

  defp organization_reference do
    %{
      "@type" => "Organization",
      "@id" => organization_id(),
      "name" => "EEF CNA",
      "url" => url(~p"/")
    }
  end

  defp english_description(container) do
    container
    |> Map.get("descriptions", [])
    |> Enum.find_value(fn
      %{"lang" => "en" <> _, "value" => value} when is_binary(value) and value != "" -> value
      _other -> nil
    end)
  end

  defp keywords(cve_id, container) do
    cwes = for %{"cweId" => cwe_id} <- CveView.cwe_descriptions(container), do: cwe_id

    severity =
      case CveView.best_cvss(container) do
        %{"baseSeverity" => severity} when is_binary(severity) -> [severity]
        _none -> []
      end

    products =
      for entry <- List.wrap(container["affected"]),
          name <- [entry["vendor"], entry["product"] || entry["packageName"]],
          is_binary(name),
          do: name

    Enum.uniq([cve_id | cwes ++ severity ++ products])
  end

  defp software(entry) do
    %{
      "@type" => "SoftwareApplication",
      "name" => entry["product"] || entry["packageName"] || CveView.package_name(entry["packageURL"]),
      "applicationCategory" => "DeveloperApplication",
      "identifier" => entry["packageURL"],
      "author" => entry["vendor"] && %{"@type" => "Organization", "name" => entry["vendor"]}
    }
  end

  defp contributor({name, types}) do
    %{
      "@type" => "Person",
      "name" => name,
      "description" => Enum.map_join(types, ", ", &CveView.humanize_credit/1)
    }
  end

  defp citation(reference) do
    %{"@type" => "WebPage", "url" => reference["url"], "name" => reference["name"]}
  end

  defp compact(%{} = map) do
    for {key, value} <- map,
        value = compact(value),
        not empty?(value),
        into: %{},
        do: {key, value}
  end

  defp compact(list) when is_list(list), do: list |> Enum.map(&compact/1) |> Enum.reject(&empty?/1)

  defp compact(value), do: value

  defp empty?(value), do: value in [nil, "", [], %{}]
end
