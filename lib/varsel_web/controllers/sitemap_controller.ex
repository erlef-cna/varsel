# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.SitemapController do
  @moduledoc """
  Serves `/sitemap.xml`: the home page, the static content pages (canonical
  extensionless URLs), a common-weaknesses root per switchable CWE view, and
  every published CVE at its canonical `.html` URL.

  "Switchable" (same set the browser's own view switcher offers — a view
  with at least one declared member, not deprecated/obsolete) rather than
  every `Varsel.CWE.View` row: a memberless view's root renders an empty
  donut with nothing under it, not a page worth a crawler's time.

  The document is rebuilt at most once every `@ttl_ms` and cached in
  `:persistent_term` — the CVE set changes rarely and rebuilding scans every
  published record, so a short cache keeps crawler hits cheap.

  Built as an XML tree and encoded rather than concatenated, so every URL is
  escaped by the encoder. Note that a bare string child of
  `Saxy.XML.element/3` is emitted raw; text goes through `characters/1`.
  """

  use VarselWeb, :controller

  import Saxy.XML

  alias Varsel.CVE
  alias Varsel.CWE
  alias Varsel.CWE.View

  @cache_key {__MODULE__, :xml}
  @ttl_ms to_timeout(minute: 10)

  # The static pages have no per-page modification date; use the build date as
  # their `lastmod` so it stays stable until the next release (each deploy
  # recompiles this module and stamps a fresh date).
  @compiled_at Date.utc_today()

  def index(conn, _params) do
    conn
    |> put_resp_content_type("text/xml")
    |> send_resp(200, cached_xml())
  end

  # Serve the cached XML while it is fresh; otherwise rebuild and re-cache. No
  # locking — a rare double build under a cold-cache stampede is harmless.
  defp cached_xml do
    now = System.monotonic_time(:millisecond)

    case :persistent_term.get(@cache_key, nil) do
      {built_at, xml} when now - built_at < @ttl_ms ->
        xml

      _stale_or_missing ->
        xml = build_xml()
        :persistent_term.put(@cache_key, {now, xml})
        xml
    end
  end

  defp build_xml do
    base = VarselWeb.Endpoint.url()

    cves =
      CVE.list_published_cve_records!(
        query: Ash.Query.select(CVE.CveRecord, []),
        load: [:cve_id, :date_updated, :date_published],
        strict?: true,
        actor: nil
      )

    views =
      CWE.list_switchable_views!(
        query: Ash.Query.select(View, [:view_id]),
        strict?: true,
        actor: nil
      )

    static = Enum.map(static_pages(), &url_entry(base <> &1, @compiled_at))

    view_roots =
      Enum.map(views, &url_entry(base <> ~p"/common-weaknesses/#{&1.view_id}", @compiled_at))

    published =
      Enum.map(cves, &url_entry(base <> ~p"/cves/#{&1.cve_id <> ".html"}", record_mod(&1)))

    urlset =
      element(
        "urlset",
        [{"xmlns", "http://www.sitemaps.org/schemas/sitemap/0.9"}],
        static ++ view_roots ++ published
      )

    Saxy.encode!(urlset, version: "1.0", encoding: "UTF-8")
  end

  defp url_entry(url, lastmod) do
    element("url", [], [
      element("loc", [], [characters(url)]),
      element("lastmod", [], [characters(Date.to_iso8601(lastmod))])
    ])
  end

  defp static_pages do
    [
      ~p"/",
      ~p"/cves",
      ~p"/scope",
      ~p"/cve-criteria",
      ~p"/coordinator-process",
      ~p"/maintainer-process",
      ~p"/security-policy",
      ~p"/data-licensing",
      ~p"/api-access",
      ~p"/contact"
    ]
  end

  # A record's last-modified day: dateUpdated, falling back to datePublished.
  defp record_mod(record) do
    DateTime.to_date(record.date_updated || record.date_published)
  end
end
