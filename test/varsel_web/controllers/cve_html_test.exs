# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveHtmlTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures, only: [seed_weakness: 2, seed_attack_pattern: 2]

  alias Varsel.CVE.CveRecord

  @cve_id "CVE-2025-48042"

  @cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.2",
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "state" => "PUBLISHED",
      "datePublished" => "2025-09-07T16:01:01.470Z",
      "dateUpdated" => "2026-05-27T15:40:15.857Z"
    },
    "containers" => %{
      "cna" => %{
        "title" => "Before action hooks may execute despite a request being forbidden",
        "descriptions" => [
          %{"lang" => "en", "value" => "Incorrect Authorization vulnerability in ash."}
        ],
        "affected" => [
          %{
            "collectionURL" => "https://repo.hex.pm",
            "packageName" => "ash",
            "packageURL" => "pkg:hex/ash",
            "defaultStatus" => "unaffected",
            "cpes" => ["cpe:2.3:a:ash-project:ash:*:*:*:*:*:elixir:*:*"],
            "modules" => ["Ash.Actions.Read"],
            "programFiles" => ["lib/ash/actions/read.ex"],
            "versions" => [
              %{
                "version" => "1.0.0",
                "lessThan" => "1.4.0",
                "status" => "affected",
                "versionType" => "semver"
              },
              %{
                "version" => "3.0.0",
                "lessThan" => "3.5.39",
                "status" => "affected",
                "versionType" => "semver"
              }
            ]
          }
        ],
        "problemTypes" => [
          %{
            "descriptions" => [
              %{
                "cweId" => "CWE-863",
                "description" => "Incorrect Authorization",
                "lang" => "en",
                "type" => "CWE"
              }
            ]
          },
          %{
            "descriptions" => [
              %{
                "cweId" => "CWE-9999",
                "description" => "Unknown to the local catalog",
                "lang" => "en",
                "type" => "CWE"
              }
            ]
          }
        ],
        "impacts" => [
          %{
            "capecId" => "CAPEC-180",
            "descriptions" => [%{"lang" => "en", "value" => "Exploiting Access Control"}]
          }
        ],
        "metrics" => [
          %{
            "cvssV4_0" => %{
              "baseScore" => 7.1,
              "baseSeverity" => "HIGH",
              "vectorString" => "CVSS:4.0/AV:N/AC:L",
              "version" => "4.0"
            }
          }
        ],
        "workarounds" => [
          %{"lang" => "en", "value" => "Disable before-action hooks on forbidden requests."}
        ],
        "configurations" => [
          %{"lang" => "en", "value" => "Set `config :ash, :strict_check?, true`."}
        ],
        "solutions" => [
          %{"lang" => "en", "value" => "Upgrade to a patched release."}
        ],
        "credits" => [
          %{"lang" => "en", "type" => "remediation developer", "value" => "Zach Daniel"}
        ],
        "references" => [
          %{
            "tags" => ["vendor-advisory"],
            "url" => "https://github.com/ash-project/ash/security/advisories/GHSA-jj4j-x5ww-cwh9",
            "name" => "GHSA-jj4j-x5ww-cwh9"
          },
          %{"tags" => ["patch"], "url" => "https://github.com/ash-project/ash/commit/abc123"}
        ]
      }
    }
  }

  defp publish(cve_json \\ @cve_json) do
    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  defp seed_catalogs do
    seed_weakness(863, "Incorrect Authorization")
    seed_attack_pattern(180, "Exploiting Trust in Client")
  end

  describe "GET /cves/:cve_id (HTML)" do
    test "renders the detail page for a published record", %{conn: conn} do
      seed_catalogs()
      publish()

      conn = get(conn, ~p"/cves/#{@cve_id}")
      body = html_response(conn, 200)

      assert body =~ @cve_id
      assert body =~ "Before action hooks may execute"
      assert body =~ "pkg:hex/ash"
      assert body =~ "7.1"
      assert body =~ "GHSA-jj4j-x5ww-cwh9"
      assert body =~ "Zach Daniel"
      assert body =~ "osv.dev/vulnerability/EEF-#{@cve_id}"
      assert body =~ ~p"/cves/#{@cve_id <> ".json"}"
    end

    test "the Am I affected? card mounts the embedded checker LiveView", %{conn: conn} do
      publish()

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ ~s(id="am-i-affected")
      assert body =~ "data-phx-session"
      assert body =~ "type your ash version to check"
    end

    test "sections render as one card each, in ToC order, 1:1 with the ToC", %{conn: conn} do
      seed_catalogs()
      publish()

      conn = get(conn, ~p"/cves/#{@cve_id}")
      body = html_response(conn, 200)

      toc_order = ~w(am-i-affected description weaknesses affected workarounds configurations
                     solutions references credits cvss-breakdown)

      toc_positions = Enum.map(toc_order, &card_position(body, &1))
      assert toc_positions == Enum.sort(toc_positions), "cards must render in ToC order"

      for id <- toc_order do
        assert body =~ ~s(id="#{id}"), "expected a ##{id} section/card"
      end
    end

    test "the CWE chip carries the catalog name, links to the local weakness catalog, and MITRE",
         %{
           conn: conn
         } do
      seed_catalogs()
      publish()

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "CWE-863"
      assert body =~ "Incorrect Authorization"
      assert body =~ "/common-weaknesses?cwe=CWE-863"
      assert body =~ "cwe.mitre.org/data/definitions/863.html"
    end

    test "a CAPEC chip carries the catalog name, its own impact description (not catalog boilerplate), and a MITRE link",
         %{
           conn: conn
         } do
      seed_catalogs()
      publish()

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "CAPEC-180"
      assert body =~ "Exploiting Trust in Client"
      assert body =~ "Exploiting Access Control"
      assert body =~ "capec.mitre.org/data/definitions/180.html"
    end

    test "the Weaknesses card never truncates the CWE catalog name — only the band chip does",
         %{conn: conn} do
      seed_weakness(
        78,
        "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
      )

      cve_json =
        put_in(@cve_json, ["containers", "cna", "problemTypes"], [
          %{
            "descriptions" => [
              %{"lang" => "en", "type" => "CWE", "cweId" => "CWE-78", "description" => "CWE-78"}
            ]
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      [_band, rest] = String.split(body, ~s(id="weaknesses"), parts: 2)
      [card, _rest] = String.split(rest, "</section>", parts: 2)
      assert card =~ "Improper Neutralization of Special Elements used in an OS Command"
      refute card =~ "text-ellipsis"
    end

    test "a catalog miss renders the id-only chip, no crash, no dangling separator", %{conn: conn} do
      # CWE-9999 is in the fixture but never seeded into the local catalog.
      publish()

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "CWE-9999"
      refute body =~ "CWE-9999</code>\n      ·"
      refute body =~ "CWE-9999 ·"
    end

    test "multi-branch affected ranges carry semver branch labels", %{conn: conn} do
      publish()

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "1.4 series"
      assert body =~ "3.5 series"
      assert body =~ "fixed in 1.4.0"
      assert body =~ "fixed in 3.5.39"
    end

    test "git-type ranges show 7-char short shas (R4), never a full 40-hex sha, and the honest no-tag note",
         %{
           conn: conn
         } do
      affected_sha = "2f81c44b1c2d3e4f5061728394a5b6c7d8e9f0a1"
      fixed_sha = "d94a7c0b1c2d3e4f5061728394a5b6c7d8e9f0a1"

      cve_json =
        put_in(@cve_json, ["containers", "cna", "affected"], [
          %{
            "collectionURL" => "https://github.com",
            "repo" => "https://github.com/acme/acme_lib",
            "packageName" => "acme/acme_lib",
            "packageURL" => "pkg:github/acme/acme_lib",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => affected_sha,
                "lessThan" => "*",
                "status" => "affected",
                "versionType" => "git"
              }
            ]
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ String.slice(affected_sha, 0, 7)
      # The full sha legitimately appears once, in the range line's `title`
      # hover attribute (R4) — but never as VISIBLE <code> text.
      assert body =~ ~s(title="#{affected_sha}")
      refute body =~ ~s(>#{affected_sha}<)
      refute body =~ fixed_sha
      assert body =~ "git — no tagged release contains the fix yet"
    end

    test "a git range with a concrete tagged fix shows R4 introduced-by/fixed-by phrasing with 7-char shas, no operators, no repeated fix",
         %{
           conn: conn
         } do
      affected_sha = "2f81c44b1c2d3e4f5061728394a5b6c7d8e9f0a1"
      fixed_sha = "d94a7c0b1c2d3e4f5061728394a5b6c7d8e9f0a1"

      cve_json =
        put_in(@cve_json, ["containers", "cna", "affected"], [
          %{
            "collectionURL" => "https://github.com",
            "repo" => "https://github.com/acme/acme_lib",
            "packageName" => "acme/acme_lib",
            "packageURL" => "pkg:github/acme/acme_lib",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => affected_sha,
                "lessThan" => fixed_sha,
                "status" => "affected",
                "versionType" => "git"
              }
            ]
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "introduced by"
      assert body =~ "fixed by"
      assert body =~ String.slice(affected_sha, 0, 7)
      assert body =~ String.slice(fixed_sha, 0, 7)
      # The full shas legitimately appear in `title` hover attributes (R4),
      # but never as VISIBLE <code> text.
      assert body =~ ~s(title="#{affected_sha}")
      assert body =~ ~s(title="#{fixed_sha}")
      refute body =~ ~s(>#{fixed_sha}<)
      refute body =~ ~s(>#{affected_sha}<)
      refute body =~ "≥"
      refute body =~ "&lt;"
    end

    test "a git range whose \"version\" is the zero sentinel renders only the fix, no phantom intro (CVE-2098-0003 shape)",
         %{conn: conn} do
      fixed_sha = "5d1b6a5d00aa11bb22cc33dd44ee55ff66aa77bb"

      cve_json =
        put_in(@cve_json, ["containers", "cna", "affected"], [
          %{
            "collectionURL" => "https://github.com",
            "repo" => "https://github.com/ash-project/ash",
            "packageName" => "ash-project/ash",
            "packageURL" => "pkg:hex/ash",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "0",
                "lessThan" => fixed_sha,
                "status" => "affected",
                "versionType" => "git"
              }
            ]
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      refute body =~ "introduced by"
      assert body =~ "fixed by"
      assert body =~ String.slice(fixed_sha, 0, 7)
      refute body =~ ~s(title="0")
    end

    test "a git-only record still gets the Am I affected? card (rev 3: no exception clause) with commit guidance, no version input",
         %{conn: conn} do
      cve_json =
        put_in(@cve_json, ["containers", "cna", "affected"], [
          %{
            "collectionURL" => "https://github.com",
            "repo" => "https://github.com/acme/acme_lib",
            "packageName" => "acme/acme_lib",
            "packageURL" => "pkg:github/acme/acme_lib",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "2f81c44b1c2d3e4f5061728394a5b6c7d8e9f0a1",
                "lessThan" => "*",
                "status" => "affected",
                "versionType" => "git"
              }
            ]
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ ~s(id="am-i-affected")
      assert body =~ "Am I affected?"
      assert body =~ "data-phx-session"
      assert body =~ "tracks affected code by commit"
    end

    test "a record mixing a checkable and a git-only package offers BOTH as pills (rev 3: pills/select count all packages)",
         %{
           conn: conn
         } do
      cve_json =
        put_in(@cve_json, ["containers", "cna", "affected"], [
          %{
            "packageName" => "ash",
            "packageURL" => "pkg:hex/ash",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "1.0.0",
                "lessThan" => "1.4.0",
                "status" => "affected",
                "versionType" => "semver"
              }
            ]
          },
          %{
            "collectionURL" => "https://github.com",
            "repo" => "https://github.com/acme/acme_lib",
            "packageName" => "acme/acme_lib",
            "packageURL" => "pkg:github/acme/acme_lib",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "2f81c44b1c2d3e4f5061728394a5b6c7d8e9f0a1",
                "lessThan" => "*",
                "status" => "affected",
                "versionType" => "git"
              }
            ]
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ ~s(id="am-i-affected")
      assert body =~ "type your ash version to check"
      assert body =~ "select-package"
      assert body =~ "pkg:hex/ash"
      assert body =~ "pkg:github/acme/acme_lib"
    end

    test "a package whose versions[] mixes semver with purl/git entries for the same range still checks",
         %{conn: conn} do
      # Real CNA shape (e.g. published CVE-2025-20759): one affected[] entry
      # can carry three versions[] rows describing the SAME boundary in
      # different schemes (purl, semver, git). Only the semver one is
      # checkable; the others must be dropped, not crash the page.
      cve_json =
        put_in(@cve_json, ["containers", "cna", "affected"], [
          %{
            "packageName" => "ash",
            "vendor" => "ash-project",
            "product" => "ash",
            "repo" => "https://github.com/ash-project/ash",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "pkg:hex/ash@0",
                "lessThan" => "pkg:hex/ash@3.5.39",
                "status" => "affected",
                "versionType" => "purl"
              },
              %{
                "version" => "0",
                "lessThan" => "3.5.39",
                "status" => "affected",
                "versionType" => "semver"
              },
              %{
                "version" => "0",
                "lessThan" => "5d1b6a5d00771fd468a509778637527b5218be9a",
                "status" => "affected",
                "versionType" => "git"
              }
            ]
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ ~s(id="am-i-affected")
      assert body =~ "data-phx-session"
    end

    test "affected card anatomy: registry + repo links, default status, cpe row, disclosure", %{
      conn: conn
    } do
      publish()

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "https://hex.pm/packages/ash"
      assert body =~ "Hex.pm"
      assert body =~ "unaffected"
      assert body =~ "cpe:2.3:a:ash-project:ash"
      assert body =~ "<details"
      assert body =~ "Ash.Actions.Read"
      assert body =~ "lib/ash/actions/read.ex"
    end

    test "a multi-package record gives every affected card a unique id, first one anchored to the ToC",
         %{conn: conn} do
      cve_json =
        put_in(@cve_json, ["containers", "cna", "affected"], [
          %{
            "packageName" => "cowlib",
            "packageURL" => "pkg:hex/cowlib",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "2.7.0",
                "lessThan" => "2.12.3",
                "status" => "affected",
                "versionType" => "semver"
              }
            ]
          },
          %{
            "packageName" => "cowboy",
            "packageURL" => "pkg:hex/cowboy",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "2.8.0",
                "lessThan" => "2.13.1",
                "status" => "affected",
                "versionType" => "semver"
              }
            ]
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ ~s(id="affected-2")
      refute body =~ ~s(id="affected-3")

      # Exactly one id="affected" (not id="affected-2" also matching a loose search).
      assert ~r/id="affected"/ |> Regex.scan(body) |> length() == 1

      assert body =~ ~s(href="#affected")
    end

    test "Workarounds, Configurations and Solutions each render their own card", %{conn: conn} do
      publish()

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ ~s(id="workarounds")
      assert body =~ "Disable before-action hooks"
      assert body =~ ~s(id="configurations")
      assert body =~ "strict_check?"
      assert body =~ ~s(id="solutions")
      assert body =~ "Upgrade to a patched release"
    end

    test "references are one flat list, advisory before patch before the rest", %{conn: conn} do
      cve_json =
        put_in(@cve_json, ["containers", "cna", "references"], [
          %{
            "tags" => ["mailing-list"],
            "url" => "https://example.com/thread",
            "name" => "thread"
          },
          %{"tags" => ["patch"], "url" => "https://github.com/ash-project/ash/commit/abc123"},
          %{
            "tags" => ["vendor-advisory"],
            "url" => "https://github.com/ash-project/ash/security/advisories/GHSA-jj4j-x5ww-cwh9",
            "name" => "GHSA-jj4j-x5ww-cwh9"
          }
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      advisory_pos = pos(body, "GHSA-jj4j-x5ww-cwh9")
      patch_pos = pos(body, "abc123")
      mailing_pos = pos(body, "thread")
      assert advisory_pos < patch_pos
      assert patch_pos < mailing_pos
    end

    test "the record's own self-referential canonical URL never appears in References, regardless of host (bug #3 regression)",
         %{conn: conn} do
      cve_json =
        put_in(@cve_json, ["containers", "cna", "references"], [
          %{"tags" => ["vendor-advisory"], "url" => "https://cna.erlef.org/cves/#{@cve_id}.html"},
          %{"tags" => ["patch"], "url" => "https://github.com/ash-project/ash/commit/abc123def"}
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      refute body =~ "cna.erlef.org/cves/#{@cve_id}"
      assert body =~ "abc123def"
    end

    test "a record whose only reference is its own self-link renders no References card and no ToC entry at all",
         %{conn: conn} do
      cve_json =
        put_in(@cve_json, ["containers", "cna", "references"], [
          %{"tags" => ["vendor-advisory"], "url" => "https://cna.erlef.org/cves/#{@cve_id}.html"}
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      refute body =~ ~s(id="references")
      refute body =~ ~s(href="#references")
    end

    test "reference row anatomy at scale: commit shas render as host/owner/repo · sha ↗, third-party-advisory joins the warn family, broken-link stays faint (not struck), untagged gets no pill",
         %{conn: conn} do
      cve_json =
        put_in(@cve_json, ["containers", "cna", "references"], [
          %{"tags" => ["third-party-advisory"], "url" => "https://example.com/mirror-writeup"},
          %{
            "tags" => ["patch"],
            "url" => "https://github.com/acme/proxy_lib/commit/00aa11bb22cc33dd44ee55ff66aa77bb88cc99dd"
          },
          %{"tags" => ["broken-link"], "url" => "https://example.com/dead-mirror"},
          %{"url" => "https://example.com/vendor-faq"}
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "github.com/acme/proxy_lib"
      assert body =~ "00aa11b"
      refute body =~ "00aa11bb22cc33dd44ee55ff66aa77bb88cc99dd<"
      assert body =~ "third-party-advisory"
      assert body =~ "text-warning"
      refute body =~ "<s>"
      refute body =~ "line-through"
      refute body =~ ~s(>https://example.com/vendor-faq<)
    end

    test "no-metrics record has no CVSS card, no CVSS ToC entry, and still shows the no-score chip",
         %{
           conn: conn
         } do
      cve_json = put_in(@cve_json, ["containers", "cna", "metrics"], [])
      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      refute body =~ ~s(id="cvss-breakdown")
      assert body =~ "no score"
    end

    test "the CVSS vector renders as its own wrapped block line with <wbr> after every slash, never break-all",
         %{conn: conn} do
      publish()

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "CVSS:4.0/<wbr"
      assert body =~ "AV:N/<wbr"
      # The vector's own <code> block carries the wrap-only-at-slash mono
      # styling (rev 3) — distinct from the cpe/component rows' break-all.
      assert body =~ ~s(font-mono text-[0.7rem] leading-[1.6])
    end

    test "CPE display unescapes the CPE 2.3 formatted-string backslash-slash escape", %{
      conn: conn
    } do
      cve_json =
        put_in(@cve_json, ["containers", "cna", "affected", Access.at(0), "cpes"], [
          "cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*"
        ])

      publish(cve_json)

      body = conn |> get(~p"/cves/#{@cve_id}") |> html_response(200)

      assert body =~ "cpe:2.3:a:erlang:erlang/otp:"
      refute body =~ "erlang\\/otp"
    end

    test "returns 404 for an unknown id", %{conn: conn} do
      conn = get(conn, ~p"/cves/CVE-0000-00000")
      assert html_response(conn, 404)
    end
  end

  describe "GET /cves/:cve_id.json still serves the raw record" do
    test "returns the cve_json", %{conn: conn} do
      publish()

      conn = get(conn, "/cves/#{@cve_id}.json")
      assert json_response(conn, 200)["cveMetadata"]["cveId"] == @cve_id
    end
  end

  describe "GET /cves/index.json is not shadowed by the html route" do
    test "returns the machine-readable index", %{conn: conn} do
      publish()

      conn = get(conn, "/cves/index.json")
      [entry] = json_response(conn, 200)
      assert entry["id"] == @cve_id
    end
  end

  defp pos(body, needle) do
    case :binary.match(body, needle) do
      {index, _length} -> index
      :nomatch -> flunk("expected to find #{inspect(needle)} in the response body")
    end
  end

  defp card_position(body, id), do: pos(body, ~s(id="#{id}"))
end
