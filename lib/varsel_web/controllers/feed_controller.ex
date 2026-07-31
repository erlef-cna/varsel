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
  `text/1` or `html_text/1`, which also map `nil` to an empty node.

  A CVE title or description is **plain text** that happens to contain markup
  characters, so what it needs depends entirely on whether the field it lands
  in is defined as HTML. The three cases below are what the W3C feed validator
  accepts, and they are not interchangeable:

    * **Atom `title`/`summary`** are typed constructs. They are declared
      `type="html"` and escaped twice — `html_text/1` escapes as HTML, then the
      encoder escapes as XML. Leaving them untyped fails whatever the encoding,
      because the validator will not accept markup it was not told about.

    * **RSS `description`** is HTML by definition, with no attribute to say
      otherwise, so it takes the same double escape. Emitted as plain text it
      fails "Invalid HTML" on the first stray `<`.

    * **RSS `title`** is the opposite: the validator treats it as *non*-HTML
      and flags any HTML entity in it, so an ordinary title like "Erlang's
      parser" fails the moment `'` becomes `&#39;`. It stays on `text/1` and
      lets the encoder do the single XML escape.

  CDATA is deliberately not used. It is raw by definition, so an escaped entity
  inside it reaches the wire verbatim and trips the same ContainsHTML rule.

  What a reader ends up showing is the original text either way: a summary
  reading `<script>` arrives as those visible characters rather than as a live
  tag, which is what a CVE summary means by it.
  """
  use VarselWeb, :controller

  import Saxy.XML

  alias Varsel.CVE

  @title "Erlang Ecosystem Foundation CNA CVEs"
  @description "CVE records published by the Erlang Ecosystem Foundation CNA."
  @prolog [version: "1.0", encoding: "UTF-8"]

  # A feed is a notification stream, not an archive: the window holds the
  # latest publications, and /cves/index.json carries the full corpus.
  @window 100

  def atom(conn, _params) do
    conn
    |> put_resp_content_type("application/atom+xml")
    |> respond(&atom_feed/2)
  end

  def rss(conn, _params) do
    conn
    |> put_resp_content_type("application/rss+xml")
    |> respond(&rss_feed/2)
  end

  # Readers echo the Last-Modified we sent as If-Modified-Since, so an
  # unchanged feed is answered 304 from the exact string match, body-free.
  #
  # The body is `Saxy.encode!` output — the encoder escapes every value in the
  # tree, some of which were HTML-escaped first (see the moduledoc), which is
  # what sobelow cannot see through.
  # sobelow_skip ["XSS.SendResp"]
  defp respond(conn, builder) do
    entries = feed_entries()
    last_modified = entries |> Enum.map(& &1.updated) |> latest()
    http_date = http_date(last_modified)

    if http_date != nil and http_date in get_req_header(conn, "if-modified-since") do
      send_resp(conn, 304, "")
    else
      conn
      |> put_last_modified(http_date)
      |> send_resp(200, Saxy.encode!(builder.(entries, last_modified), @prolog))
    end
  end

  defp put_last_modified(conn, nil), do: conn
  defp put_last_modified(conn, http_date), do: put_resp_header(conn, "last-modified", http_date)

  defp feed_entries do
    query =
      CVE.CveRecord
      |> Ash.Query.select([:cve_json])
      |> Ash.Query.limit(@window)

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

  defp latest(datetimes) do
    datetimes |> Enum.reject(&is_nil/1) |> Enum.max(DateTime, fn -> nil end)
  end

  defp description(record) do
    record.cve_json
    |> get_in(["containers", "cna", "descriptions"])
    |> List.wrap()
    |> Enum.find_value("", fn d -> if d["lang"] == "en", do: d["value"] end)
  end

  defp entry_url(cve_id), do: url(~p"/cves/#{cve_id <> ".html"}")

  ## ---------------------------------------------------------------- Atom

  defp atom_feed(entries, updated) do
    self_url = url(~p"/feed.atom")

    element("feed", [{"xmlns", "http://www.w3.org/2005/Atom"}], [
      element("title", [{"type", "html"}], html_text(@title)),
      element("subtitle", [{"type", "html"}], html_text(@description)),
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
      element("title", [{"type", "html"}], html_text("#{entry.cve_id}: #{entry.title}")),
      element("link", [{"href", entry_url}, {"rel", "alternate"}, {"type", "text/html"}], []),
      element("published", [], text(iso(entry.published))),
      element("updated", [], text(iso(entry.updated))),
      element("summary", [{"type", "html"}], html_text(entry.summary))
    ])
  end

  ## ---------------------------------------------------------------- RSS

  defp rss_feed(entries, build_date) do
    channel =
      [
        element("title", [], text(@title)),
        element("description", [], html_text(@description)),
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
      element("description", [], html_text(entry.summary))
    ])
  end

  ## ---------------------------------------------------------------- helpers

  # `characters/1` is what escapes; a bare string child would be emitted raw.
  defp text(nil), do: []
  defp text(value), do: [characters(to_string(value))]

  # Escaped twice — once as HTML here, then again as XML by the encoder — for
  # the fields a reader renders as HTML. It undoes the XML layer when parsing,
  # renders what is left as HTML, and displays the original text; a summary
  # reading `<script>` therefore shows those characters instead of becoming a
  # live tag. Emitting these as plain text instead makes the W3C validator
  # parse the prose as HTML and fail on the first stray `<` ("Invalid HTML").
  defp html_text(nil), do: []

  defp html_text(value) do
    escaped =
      value
      |> to_string()
      |> Phoenix.HTML.html_escape()
      |> Phoenix.HTML.safe_to_string()

    [characters(escaped)]
  end

  defp iso(nil), do: ""
  defp iso(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp rfc822(nil), do: ""
  defp rfc822(%DateTime{} = dt), do: Calendar.strftime(dt, "%a, %d %b %Y %H:%M:%S +0000")

  # HTTP-date (RFC 9110): second precision, GMT.
  defp http_date(nil), do: nil

  defp http_date(%DateTime{} = dt) do
    dt |> DateTime.truncate(:second) |> Calendar.strftime("%a, %d %b %Y %H:%M:%S GMT")
  end
end
