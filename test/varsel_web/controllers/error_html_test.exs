# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ErrorHTMLTest do
  use VarselWeb.ConnCase, async: true

  test "renders 404.html through the shared shell", %{conn: conn} do
    body = conn |> get("/nonexistent-route") |> html_response(404)

    assert body =~ "Page not found"
    assert body =~ "Error · HTTP 404"
  end

  test "renders 404.html with exactly one nav and one footer", %{conn: conn} do
    body = conn |> get("/nonexistent-route") |> html_response(404)

    assert ~r/<header class="eef-band/ |> Regex.scan(body) |> length() == 1
    assert ~r/<footer class="eef-band/ |> Regex.scan(body) |> length() == 1
  end

  test "renders 500.html through the shared shell" do
    body =
      Phoenix.Template.render_to_string(VarselWeb.ErrorHTML, "500", "html",
        conn: %{
          request_path: "/cves/CVE-2025-1234.html"
        }
      )

    assert body =~ "Something went wrong on our side"
    assert body =~ "Error · HTTP 500"
    assert body =~ "Try again"
  end

  test "renders 401.html with the sign-in headline and eyebrow" do
    body = Phoenix.Template.render_to_string(VarselWeb.ErrorHTML, "401", "html", [])

    assert body =~ "Please sign in to continue"
    assert body =~ "Error · HTTP 401"
    assert body =~ "Sign in"
  end

  test "renders 403.html with the access-denied headline and eyebrow" do
    body = Phoenix.Template.render_to_string(VarselWeb.ErrorHTML, "403", "html", [])

    assert body =~ "You don't have access to this page"
    assert body =~ "Error · HTTP 403"
    refute body =~ "Sign in"
  end

  test "falls back to a generic shell for an arbitrary status" do
    body =
      Phoenix.Template.render_to_string(VarselWeb.ErrorHTML, "406", "html",
        conn: %{
          request_path: "/common-weaknesses"
        }
      )

    assert body =~ "Error · HTTP 406"
    assert body =~ "Not Acceptable"
    assert body =~ "Your request couldn't be completed."
    refute body =~ "Try again"
  end

  # Reason phrases run from "Gone" (4 chars) to "Request Header Fields Too Large"
  # (31); the band must show them in full, so the title carries no `truncate`
  # and the band no fixed height.
  test "generic shell renders the full reason phrase at both length extremes" do
    for {status, phrase} <- [{"410", "Gone"}, {"431", "Request Header Fields Too Large"}] do
      body =
        Phoenix.Template.render_to_string(VarselWeb.ErrorHTML, status, "html", conn: %{request_path: "/x"})

      assert body =~ "Error · HTTP #{status}"
      assert body =~ phrase
      refute body =~ "truncate"
    end
  end

  test "renders arbitrary garbage template names as a 500 in the generic shell" do
    body = Phoenix.Template.render_to_string(VarselWeb.ErrorHTML, "not-a-status", "html", [])

    assert body =~ "Error · HTTP 500"
    assert body =~ "Your request couldn't be completed."
  end

  # The retry link needs the URL that failed, and a 500 can be rendered with no
  # conn assigned at all — the row is dropped rather than guessing a target.
  test "500 page omits the retry row when no conn is assigned" do
    body = Phoenix.Template.render_to_string(VarselWeb.ErrorHTML, "500", "html", [])

    assert body =~ "Something went wrong on our side"
    refute body =~ "Try again"
  end
end
