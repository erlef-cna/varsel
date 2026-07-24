# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.SitemapController do
  @moduledoc """
  Serves `/sitemap.xml`: the home page, the static content pages (canonical
  extensionless URLs), and every published CVE at its canonical `.html` URL.

  The document is rebuilt at most once every `@ttl_ms` and cached in
  `:persistent_term` — the CVE set changes rarely and rebuilding scans every
  published record, so a short cache keeps crawler hits cheap.
  """

  use VarselWeb, :controller

  alias Varsel.CVE

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
    cves =
      CVE.list_published_cve_records!(
        load: [:cve_id, :date_updated, :date_published],
        strict?: true,
        actor: nil
      )

    VarselWeb.Endpoint.url()
    |> SitemapBuilder.new()
    |> SitemapBuilder.add(static_pages(), &%SitemapBuilder{url: &1, lastmod: @compiled_at})
    |> SitemapBuilder.add(
      cves,
      &%SitemapBuilder{url: ~p"/cves/#{&1.cve_id <> ".html"}", lastmod: record_mod(&1)}
    )
    |> SitemapBuilder.generate()
  end

  defp static_pages do
    [
      ~p"/",
      ~p"/cves",
      ~p"/common-weaknesses",
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
