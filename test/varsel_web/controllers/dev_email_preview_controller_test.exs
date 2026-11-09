# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.DevEmailPreviewControllerTest do
  use VarselWeb.ConnCase, async: true

  defp document(conn), do: conn |> html_response(200) |> LazyHTML.from_document()

  test "lists every email and previews the first by default", %{conn: conn} do
    doc = conn |> get("/dev/emails") |> document()

    links = LazyHTML.query(doc, "#email-preview-list a")
    hrefs = Enum.map(links, &(&1 |> LazyHTML.attribute("href") |> hd()))

    assert "/dev/emails?email=digest" in hrefs
    assert "/dev/emails?email=invite-github" in hrefs
    assert "/dev/emails?email=immediate-comment_posted" in hrefs

    assert [_] = doc |> LazyHTML.query("#email-preview-html") |> Enum.to_list()
    assert [_] = doc |> LazyHTML.query("#email-preview-text pre") |> Enum.to_list()
  end

  test "renders every sample without raising", %{conn: conn} do
    hrefs =
      conn
      |> get("/dev/emails")
      |> document()
      |> LazyHTML.query("#email-preview-list a")
      |> Enum.map(&(&1 |> LazyHTML.attribute("href") |> hd()))

    for href <- hrefs do
      text =
        build_conn()
        |> get(href)
        |> document()
        |> LazyHTML.query("#email-preview-text pre")
        |> LazyHTML.text()

      assert text =~ "http"
    end
  end

  test "shows the digest's text part", %{conn: conn} do
    text =
      conn
      |> get("/dev/emails", email: "digest")
      |> document()
      |> LazyHTML.query("#email-preview-text pre")
      |> LazyHTML.text()

    assert text =~ "3 × New comment"
  end

  test "an unknown email is a 404", %{conn: conn} do
    conn = get(conn, "/dev/emails", email: "nope")

    assert [_] =
             conn
             |> html_response(404)
             |> LazyHTML.from_document()
             |> LazyHTML.query("#email-preview-missing")
             |> Enum.to_list()
  end
end
