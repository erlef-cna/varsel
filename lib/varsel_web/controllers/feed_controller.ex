# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.FeedController do
  @moduledoc """
  Atom and RSS feeds of published CVE records, ported from the Jekyll site's
  `feed.atom` / `feed.rss`. Entries are ordered newest-published first.

  The documents are built as XML rather than as strings: every value goes
  into the tree as an element, an attribute, or `Saxy.XML.characters/1`, and
  the encoder is what escapes it. Nothing here concatenates markup, so no
  value — an advisory title or a summary — can close a tag or open an
  attribute.

  Links are `~p` routes resolved against the endpoint, so a feed names the
  configured host rather than whichever one the request carried.

  Note that a bare string child of `Saxy.XML.element/3` is emitted **raw**;
  only `characters/1` escapes. Every text node below therefore goes through
  `text/1`, which also maps `nil` to an empty node.
  """
  use VarselWeb, :controller

  import Saxy.XML

  alias Varsel.CVE

  @title "Erlang Ecosystem Foundation CNA CVEs"
  @description "CVE records published by the Erlang Ecosystem Foundation CNA."
  @prolog [version: "1.0", encoding: "UTF-8"]

  def atom(conn, _params) do
    conn
    |> put_resp_content_type("application/atom+xml")
    |> send_resp(200, Saxy.encode!(atom_feed(feed_entries()), @prolog))
  end

  def rss(conn, _params) do
    conn
    |> put_resp_content_type("application/rss+xml")
    |> send_resp(200, Saxy.encode!(rss_feed(feed_entries()), @prolog))
  end

  defp feed_entries do
    query = Ash.Query.select(CVE.CveRecord, [:cve_json])

    [
      load: [:cve_id, :title, :date_published, :date_updated],
      actor: nil,
      strict?: true,
      query: query
    ]
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

  defp entry_url(cve_id), do: url(~p"/cves/#{cve_id <> ".html"}")

  ## ---------------------------------------------------------------- Atom

  defp atom_feed(entries) do
    updated = entries |> List.first(%{}) |> Map.get(:published)
    self_url = url(~p"/feed.atom")

    element("feed", [{"xmlns", "http://www.w3.org/2005/Atom"}], [
      element("title", [], text(@title)),
      element("subtitle", [], text(@description)),
      element(
        "link",
        [{"href", self_url}, {"rel", "self"}, {"type", "application/atom+xml"}],
        []
      ),
      element(
        "link",
        [{"href", url(~p"/cves")}, {"rel", "alternate"}, {"type", "text/html"}],
        []
      ),
      element("id", [], text(self_url)),
      element("updated", [], text(iso(updated))),
      element("author", [], [
        element("name", [], text(@title)),
        element("uri", [], text(url(~p"/")))
      ])
      | Enum.map(entries, &atom_entry/1)
    ])
  end

  defp atom_entry(entry) do
    entry_url = entry_url(entry.cve_id)

    element("entry", [], [
      element("id", [], text(entry_url)),
      element("title", [], text("#{entry.cve_id}: #{entry.title}")),
      element("link", [{"href", entry_url}, {"rel", "alternate"}, {"type", "text/html"}], []),
      element("published", [], text(iso(entry.published))),
      element("updated", [], text(iso(entry.updated))),
      element("summary", [], text(entry.summary))
    ])
  end

  ## ---------------------------------------------------------------- RSS

  defp rss_feed(entries) do
    build_date = entries |> List.first(%{}) |> Map.get(:published)

    channel =
      [
        element("title", [], text(@title)),
        element("description", [], text(@description)),
        element("link", [], text(url(~p"/cves"))),
        element(
          "atom:link",
          [{"href", url(~p"/feed.rss")}, {"rel", "self"}, {"type", "application/rss+xml"}],
          []
        ),
        element("lastBuildDate", [], text(rfc822(build_date)))
        | Enum.map(entries, &rss_item/1)
      ]

    element(
      "rss",
      [{"version", "2.0"}, {"xmlns:atom", "http://www.w3.org/2005/Atom"}],
      [element("channel", [], channel)]
    )
  end

  defp rss_item(entry) do
    entry_url = entry_url(entry.cve_id)

    element("item", [], [
      element("title", [], text("#{entry.cve_id}: #{entry.title}")),
      element("link", [], text(entry_url)),
      element("guid", [{"isPermaLink", "true"}], text(entry_url)),
      element("pubDate", [], text(rfc822(entry.published))),
      element("description", [], text(entry.summary))
    ])
  end

  ## ---------------------------------------------------------------- helpers

  # `characters/1` is what escapes; a bare string child would be emitted raw.
  defp text(nil), do: []
  defp text(value), do: [characters(to_string(value))]

  defp iso(nil), do: ""
  defp iso(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp rfc822(nil), do: ""
  defp rfc822(%DateTime{} = dt), do: Calendar.strftime(dt, "%a, %d %b %Y %H:%M:%S +0000")
end
