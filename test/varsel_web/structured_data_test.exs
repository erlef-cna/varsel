# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.StructuredDataTest do
  @moduledoc """
  The schema.org JSON-LD each public page carries in its head.
  """

  use VarselWeb.ConnCase, async: true

  alias Varsel.CVE.CveRecord

  @cve_id "CVE-2025-12345"

  defp publish!(title) do
    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => @cve_id,
        "state" => "PUBLISHED",
        "datePublished" => "2026-04-27T12:00:00.000Z",
        "dateUpdated" => "2026-04-28T12:00:00.000Z"
      },
      "containers" => %{
        "cna" => %{
          "title" => title,
          "descriptions" => [%{"lang" => "en", "value" => "A test vulnerability."}],
          "affected" => [
            %{"vendor" => "Acme", "product" => "acme_lib", "packageURL" => "pkg:hex/acme_lib"}
          ],
          "problemTypes" => [
            %{"descriptions" => [%{"cweId" => "CWE-79", "lang" => "en", "type" => "CWE"}]}
          ],
          "metrics" => [
            %{
              "cvssV4_0" => %{
                "baseScore" => 5.3,
                "baseSeverity" => "MEDIUM",
                "vectorString" => "CVSS:4.0"
              }
            }
          ],
          "credits" => [
            %{"lang" => "en", "value" => "Alice", "type" => "finder"},
            %{"lang" => "en", "value" => "Alice", "type" => "remediation_developer"}
          ],
          "references" => [
            %{"url" => "https://example.com/advisory", "name" => "Advisory"},
            %{"url" => "https://example.com/scheme", "tags" => ["x_version-scheme"]}
          ]
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  defp json_ld(conn) do
    [script] =
      conn
      |> html_response(200)
      |> LazyHTML.from_document()
      |> LazyHTML.query(~s(script[type="application/ld+json"]))
      |> Enum.to_list()

    script |> LazyHTML.text() |> JSON.decode!()
  end

  defp absolute(path), do: VarselWeb.Endpoint.url() <> path

  test "the home page names the CNA and the site", %{conn: conn} do
    assert %{"@context" => "https://schema.org", "@graph" => [organization, website]} =
             conn |> get(~p"/") |> json_ld()

    assert %{
             "@type" => "Organization",
             "name" => "EEF CNA",
             "email" => "cna@erlef.org",
             "parentOrganization" => %{"name" => "Erlang Ecosystem Foundation"}
           } = organization

    assert organization["logo"] == absolute("/apple-touch-icon.png")
    assert %{"@type" => "WebSite", "publisher" => %{"@id" => id}} = website
    assert id == organization["@id"]
  end

  test "the contact page names how to reach the CNA, and no person", %{conn: conn} do
    assert %{"@type" => "ContactPage", "mainEntity" => organization} =
             conn |> get(~p"/contact") |> json_ld()

    assert %{"contactPoint" => %{"email" => "cna@erlef.org", "url" => report_url}} = organization
    assert report_url == absolute("/report")
    refute Map.has_key?(organization, "member")
  end

  test "the CVE list describes the dataset and its downloads", %{conn: conn} do
    assert %{
             "@type" => "DataCatalog",
             "dataset" => %{"@type" => "Dataset", "distribution" => downloads}
           } =
             conn |> get(~p"/cves") |> json_ld()

    assert Enum.map(downloads, & &1["contentUrl"]) == [
             absolute("/cves/index.json"),
             absolute("/osv/all.json")
           ]
  end

  test "a CVE page describes the CVE from the record", %{conn: conn} do
    publish!("Header injection in acme_lib")

    article = conn |> get(~p"/cves/#{@cve_id <> ".html"}") |> json_ld()

    assert %{
             "@type" => "TechArticle",
             "identifier" => @cve_id,
             "headline" => "Header injection in acme_lib",
             "description" => "A test vulnerability.",
             "datePublished" => "2026-04-27T12:00:00.000Z",
             "dateModified" => "2026-04-28T12:00:00.000Z",
             "keywords" => [@cve_id, "CWE-79", "MEDIUM", "Acme", "acme_lib"],
             "about" => [
               %{
                 "@type" => "SoftwareApplication",
                 "name" => "acme_lib",
                 "identifier" => "pkg:hex/acme_lib"
               }
             ],
             "contributor" => [
               %{"name" => "Alice", "description" => "Finder, Remediation developer"}
             ],
             "citation" => [%{"url" => "https://example.com/advisory", "name" => "Advisory"}]
           } = article

    assert article["url"] == absolute("/cves/#{@cve_id}.html")
    assert article["sameAs"] == "https://www.cve.org/CVERecord?id=#{@cve_id}"
    assert [%{"contentUrl" => json_url}] = article["encoding"]
    assert json_url == absolute("/cves/#{@cve_id}.json")
  end

  test "a value that closes the script element stays inside the document", %{conn: conn} do
    title = ~s(</script><b id="injected">x</b>)
    publish!(title)

    conn = get(conn, ~p"/cves/#{@cve_id <> ".html"}")

    assert %{"headline" => ^title} = json_ld(conn)

    assert conn
           |> html_response(200)
           |> LazyHTML.from_document()
           |> LazyHTML.query("head b#injected")
           |> Enum.empty?()
  end

  test "a page without a document carries none", %{conn: conn} do
    html = conn |> get(~p"/scope") |> html_response(200)

    assert html
           |> LazyHTML.from_document()
           |> LazyHTML.query(~s(script[type="application/ld+json"]))
           |> Enum.empty?()
  end
end
