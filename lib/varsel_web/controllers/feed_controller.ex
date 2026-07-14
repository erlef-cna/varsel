# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.FeedController do
  @moduledoc """
  Atom and RSS feeds of published CVE records, ported from the Jekyll site's
  `feed.atom` / `feed.rss`. Entries are ordered newest-published first.
  """
  use VarselWeb, :controller

  alias Varsel.CVE

  @title "Erlang Ecosystem Foundation CNA CVEs"
  @description "CVE records published by the Erlang Ecosystem Foundation CNA."

  def atom(conn, _params) do
    entries = feed_entries()

    conn
    |> put_resp_content_type("application/atom+xml")
    |> send_resp(200, atom_xml(entries, base_url(conn)))
  end

  def rss(conn, _params) do
    entries = feed_entries()

    conn
    |> put_resp_content_type("application/rss+xml")
    |> send_resp(200, rss_xml(entries, base_url(conn)))
  end

  defp feed_entries do
    [load: [:cve_id, :title, :date_published, :date_updated], actor: nil]
    |> CVE.list_published_cve_records!()
    |> Enum.map(fn record ->
      %{
        cve_id: record.cve_id,
        title: record.title || record.cve_id,
        summary: description(record),
        published: record.date_published,
        updated: record.date_updated || record.date_published
      }
    end)
  end

  defp description(record) do
    record.cve_json
    |> get_in(["containers", "cna", "descriptions"])
    |> List.wrap()
    |> Enum.find_value("", fn d -> if d["lang"] == "en", do: d["value"] end)
  end

  defp base_url(conn), do: "#{conn.scheme}://#{conn.host}#{port_suffix(conn)}"

  defp port_suffix(%{scheme: :http, port: 80}), do: ""
  defp port_suffix(%{scheme: :https, port: 443}), do: ""
  defp port_suffix(%{port: port}), do: ":#{port}"

  ## ---------------------------------------------------------------- Atom

  defp atom_xml(entries, base) do
    updated = entries |> List.first(%{}) |> Map.get(:published)

    """
    <?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title>#{esc(@title)}</title>
      <subtitle>#{esc(@description)}</subtitle>
      <link href="#{base}/feed.atom" rel="self" type="application/atom+xml"/>
      <link href="#{base}/cves" rel="alternate" type="text/html"/>
      <id>#{base}/feed.atom</id>
      <updated>#{iso(updated)}</updated>
      <author><name>#{esc(@title)}</name><uri>#{base}</uri></author>
    #{Enum.map_join(entries, "\n", &atom_entry(&1, base))}
    </feed>
    """
  end

  defp atom_entry(entry, base) do
    url = "#{base}/cves/#{entry.cve_id}"

    """
      <entry>
        <id>#{url}</id>
        <title>#{esc(entry.cve_id)}: #{esc(entry.title)}</title>
        <link href="#{url}" rel="alternate" type="text/html"/>
        <published>#{iso(entry.published)}</published>
        <updated>#{iso(entry.updated)}</updated>
        <summary>#{esc(entry.summary)}</summary>
      </entry>\
    """
  end

  ## ---------------------------------------------------------------- RSS

  defp rss_xml(entries, base) do
    build_date = entries |> List.first(%{}) |> Map.get(:published)

    """
    <?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
      <channel>
        <title>#{esc(@title)}</title>
        <description>#{esc(@description)}</description>
        <link>#{base}/cves</link>
        <atom:link href="#{base}/feed.rss" rel="self" type="application/rss+xml"/>
        <lastBuildDate>#{rfc822(build_date)}</lastBuildDate>
    #{Enum.map_join(entries, "\n", &rss_item(&1, base))}
      </channel>
    </rss>
    """
  end

  defp rss_item(entry, base) do
    url = "#{base}/cves/#{entry.cve_id}"

    """
        <item>
          <title>#{esc(entry.cve_id)}: #{esc(entry.title)}</title>
          <link>#{url}</link>
          <guid isPermaLink="true">#{url}</guid>
          <pubDate>#{rfc822(entry.published)}</pubDate>
          <description>#{esc(entry.summary)}</description>
        </item>\
    """
  end

  ## ---------------------------------------------------------------- helpers

  defp esc(nil), do: ""

  defp esc(text) do
    text
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&apos;")
  end

  defp iso(nil), do: ""
  defp iso(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp rfc822(nil), do: ""
  defp rfc822(%DateTime{} = dt), do: Calendar.strftime(dt, "%a, %d %b %Y %H:%M:%S +0000")
end
