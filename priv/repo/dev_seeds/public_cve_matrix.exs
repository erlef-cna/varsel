# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Dev-only seed: a matrix of published CVE records covering every data shape
# the public detail page must render — modeled on real MITRE-published records
# (multi-representation versions[], purl-prefixed boundaries, CAPEC
# restatements), not idealized fixtures. Idempotent: reseeding replaces the
# whole CVE-2098-* range. Run with:
#
#     mix run priv/repo/dev_seeds/public_cve_matrix.exs
#
# ⚠️ Never run against anything but a dev database. These records exist only
# in the local DB — nothing here talks to MITRE.

import Ecto.Query

alias Varsel.CVE.CveRecord
alias Varsel.Repo

defmodule DevSeed.PublicCveMatrix do
  @moduledoc false
  @org_id "b53170e7-214f-4a6f-b188-8dd5cb245ca1"

  def run do
    Repo.delete_all(
      from(r in "cve_records",
        where: fragment("cve_json->'cveMetadata'->>'cveId' LIKE 'CVE-2098-%'")
      )
    )

    Enum.each(records(), fn {cve_id, published_at, cna} ->
      Ash.Seed.seed!(CveRecord, %{
        state: :published,
        cve_json: %{
          "dataType" => "CVE_RECORD",
          "dataVersion" => "5.1",
          "cveMetadata" => %{
            "cveId" => cve_id,
            "state" => "PUBLISHED",
            "assignerOrgId" => @org_id,
            "assignerShortName" => "EEF",
            "dateReserved" => published_at,
            "datePublished" => published_at,
            "dateUpdated" => published_at
          },
          "containers" => %{
            "cna" =>
              Map.merge(
                %{
                  "providerMetadata" => %{"orgId" => @org_id, "shortName" => "EEF"},
                  "x_generator" => %{"engine" => "Varsel dev seed"}
                },
                cna
              )
          }
        }
      })
    end)

    IO.puts("Seeded #{length(records())} matrix records (CVE-2098-*).")
  end

  defp en(value), do: [%{"lang" => "en", "value" => value}]

  defp prose(markdown_ish), do: en(markdown_ish)

  defp cwe(id, name),
    do: %{"descriptions" => [%{"lang" => "en", "type" => "CWE", "cweId" => id, "description" => "#{id} #{name}"}]}

  defp capec_restated(id, name), do: %{"capecId" => id, "descriptions" => en("#{id} #{name}")}

  defp capec_prose(id, text), do: %{"capecId" => id, "descriptions" => en(text)}

  defp cvss4(vector, score, severity),
    do: %{"cvssV4_0" => %{"version" => "4.0", "vectorString" => vector, "baseScore" => score, "baseSeverity" => severity}}

  @medium_vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
  @critical_vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:N/AU:Y/R:A/V:D/RE:L/U:Amber"

  defp ref(url, tags), do: %{"url" => url, "tags" => tags}

  defp records do
    [
      # 1 — happy path: one hex package, clean semver, distinct CAPEC prose,
      # every prose section, full reference spread, credits.
      {"CVE-2098-0001", "2026-01-05T10:00:00.000Z",
       %{
         "title" => "Plug session fixation via crafted cookie in plug_session_store",
         "descriptions" =>
           prose(
             "The `plug_session_store` library accepts a session identifier from an incoming cookie without regenerating it after privilege changes, allowing session fixation.\n\nAn attacker who can plant a cookie (for example via a subdomain) retains the session after the victim authenticates."
           ),
         "problemTypes" => [cwe("CWE-384", "Session Fixation")],
         "impacts" => [
           capec_prose(
             "CAPEC-61",
             "An attacker plants a known session id before login; the application keeps it after authentication, handing the attacker the authenticated session."
           )
         ],
         "metrics" => [cvss4(@medium_vector, 6.9, "MEDIUM")],
         "affected" => [
           %{
             "vendor" => "acme",
             "product" => "plug_session_store",
             "packageName" => "plug_session_store",
             "collectionURL" => "https://hex.pm",
             "packageURL" => "pkg:hex/plug_session_store",
             "repo" => "https://github.com/acme/plug_session_store",
             "defaultStatus" => "unaffected",
             "modules" => ["PlugSessionStore.Cookie"],
             "programFiles" => ["lib/plug_session_store/cookie.ex"],
             "programRoutines" => [%{"name" => "PlugSessionStore.Cookie.fetch/2"}],
             "versions" => [
               %{
                 "version" => "0.4.0",
                 "lessThan" => "1.2.3",
                 "status" => "affected",
                 "versionType" => "semver",
                 "changes" => [%{"at" => "1.2.3", "status" => "unaffected"}]
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0001.html", ["vendor-advisory"]),
           ref(
             "https://github.com/acme/plug_session_store/commit/ab34fe129001d5c2b7a90a1f34c2d5e6f7089a1b",
             ["patch"]
           ),
           ref("https://example.com/writeup", ["technical-description"]),
           ref("https://osv.dev/vulnerability/EEF-CVE-2098-0001", ["related"])
         ],
         "credits" => [
           %{"lang" => "en", "type" => "finder", "value" => "Maria Kowalski"},
           %{"lang" => "en", "type" => "remediation developer", "value" => "acme security team"}
         ],
         "workarounds" => prose("Set `regenerate: :always` in the session store options."),
         "configurations" => prose("Only applications using cookie-backed sessions are affected."),
         "solutions" => prose("Upgrade to `plug_session_store` 1.2.3 or later.")
       }},

      # 2 — real-world OTP shape verbatim: THREE representations of the same
      # ranges (purl w/ purl@version bounds, otp tags, git shas), defaultStatus
      # unknown, CAPEC restatement, CPE, modules/files/routines.
      {"CVE-2098-0002", "2026-01-12T10:00:00.000Z",
       %{
         "title" => "ssh_sftpd unbounded memory growth on crafted SFTP packets",
         "descriptions" =>
           prose(
             "The SFTP daemon in Erlang/OTP's `ssh` application allocates response buffers from attacker-controlled length fields without limits, allowing memory exhaustion."
           ),
         "problemTypes" => [
           cwe("CWE-770", "Allocation of Resources Without Limits or Throttling")
         ],
         "impacts" => [capec_restated("CAPEC-130", "Excessive Allocation")],
         "metrics" => [cvss4(@medium_vector, 6.9, "MEDIUM")],
         "affected" => [
           %{
             "vendor" => "Erlang",
             "product" => "OTP",
             "packageName" => "ssh",
             "packageURL" =>
               "pkg:otp/ssh?repository_url=https%3A%2F%2Fgithub.com%2Ferlang%2Fotp&vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Ferlang%2Fotp.git",
             "repo" => "https://github.com/erlang/otp",
             "cpes" => ["cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*"],
             "defaultStatus" => "unknown",
             "modules" => ["ssh_sftp", "ssh_sftpd"],
             "programFiles" => ["lib/ssh/src/ssh_sftpd.erl"],
             "programRoutines" => [%{"name" => "ssh_sftpd:handle_op/4"}],
             "versions" => [
               %{
                 "version" => "pkg:otp/ssh@3.0.1",
                 "lessThan" => "pkg:otp/ssh@*",
                 "status" => "affected",
                 "versionType" => "purl",
                 "changes" => [
                   %{"at" => "pkg:otp/ssh@5.3.3", "status" => "unaffected"},
                   %{"at" => "pkg:otp/ssh@5.2.11.3", "status" => "unaffected"},
                   %{"at" => "pkg:otp/ssh@5.1.4.12", "status" => "unaffected"}
                 ]
               },
               %{
                 "version" => "17.0",
                 "lessThan" => "*",
                 "status" => "affected",
                 "versionType" => "otp",
                 "changes" => [
                   %{"at" => "28.0.3", "status" => "unaffected"},
                   %{"at" => "27.3.4.3", "status" => "unaffected"},
                   %{"at" => "26.2.5.15", "status" => "unaffected"}
                 ]
               },
               %{
                 "version" => "07b8f441ca711f9812fad9e9115bab3c3aa92f79",
                 "lessThan" => "*",
                 "status" => "affected",
                 "versionType" => "git",
                 "changes" => [
                   %{
                     "at" => "5f9af63eec4657a37663828d206517828cb9f288",
                     "status" => "unaffected"
                   },
                   %{"at" => "d49efa2d4fa9e6f7ee658719cd76ffe7a33c2401", "status" => "unaffected"}
                 ]
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0002.html", ["vendor-advisory"]),
           ref("https://github.com/erlang/otp/commit/5f9af63eec4657a37663828d206517828cb9f288", [
             "patch"
           ])
         ],
         "credits" => [%{"lang" => "en", "type" => "finder", "value" => "anonymous reporter"}]
       }},

      # 3 — ash-style mess: purl@version bounds INCLUDING a zero lower bound,
      # the same range duplicated in clean semver, plus a bare git sha range.
      {"CVE-2098-0003", "2026-02-02T10:00:00.000Z",
       %{
         "title" => "Policy bypass in bulk actions in ash_framework_lib",
         "descriptions" => prose("Bulk destroys skip field policies when the actor is set after query build."),
         "problemTypes" => [cwe("CWE-863", "Incorrect Authorization")],
         "impacts" => [
           capec_restated("CAPEC-1", "Accessing Functionality Not Properly Constrained by ACLs")
         ],
         "metrics" => [cvss4(@medium_vector, 5.3, "MEDIUM")],
         "affected" => [
           %{
             "vendor" => "ash-project",
             "product" => "ash",
             "packageName" => "ash",
             "packageURL" => "pkg:hex/ash",
             "repo" => "https://github.com/ash-project/ash",
             "cpes" => ["cpe:2.3:a:ash-project:ash:*:*:*:*:*:*:*:*"],
             "defaultStatus" => "unaffected",
             "versions" => [
               %{
                 "version" => "pkg:hex/ash@0",
                 "lessThan" => "pkg:hex/ash@3.5.39",
                 "status" => "affected",
                 "versionType" => "purl",
                 "changes" => [%{"at" => "pkg:hex/ash@3.5.39", "status" => "unaffected"}]
               },
               %{
                 "version" => "0",
                 "lessThan" => "3.5.39",
                 "status" => "affected",
                 "versionType" => "semver",
                 "changes" => [%{"at" => "3.5.39", "status" => "unaffected"}]
               },
               %{
                 "version" => "0",
                 "lessThan" => "5d1b6a5d00aa11bb22cc33dd44ee55ff66aa77bb",
                 "status" => "affected",
                 "versionType" => "git",
                 "changes" => [
                   %{"at" => "5d1b6a5d00aa11bb22cc33dd44ee55ff66aa77bb", "status" => "unaffected"}
                 ]
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0003.html", ["vendor-advisory"]),
           ref(
             "https://github.com/ash-project/ash/commit/5d1b6a5d00aa11bb22cc33dd44ee55ff66aa77bb",
             ["patch"]
           )
         ]
       }},

      # 4 — no metrics at all: band without severity chip, no CVSS card.
      {"CVE-2098-0004", "2026-02-10T10:00:00.000Z",
       %{
         "title" => "Timing oracle in constant_time_compare fallback",
         "descriptions" => prose("The pure-Elixir fallback comparator returns early on length mismatch."),
         "problemTypes" => [cwe("CWE-208", "Observable Timing Discrepancy")],
         "affected" => [
           %{
             "vendor" => "acme",
             "product" => "secure_compare",
             "packageURL" => "pkg:hex/secure_compare",
             "defaultStatus" => "unaffected",
             "versions" => [
               %{
                 "version" => "0.1.0",
                 "lessThan" => "0.9.1",
                 "status" => "affected",
                 "versionType" => "semver",
                 "changes" => [%{"at" => "0.9.1", "status" => "unaffected"}]
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0004.html", ["vendor-advisory"])
         ]
       }},

      # 5 — minimal: no title (band falls back to id), no CWE/CAPEC (weakness
      # card absent), single reference, description only.
      {"CVE-2098-0005", "2026-02-14T10:00:00.000Z",
       %{
         "descriptions" => prose("Reserved-then-published record with the minimum viable container."),
         "metrics" => [cvss4(@medium_vector, 2.3, "LOW")],
         "affected" => [
           %{
             "vendor" => "acme",
             "product" => "tiny_lib",
             "packageURL" => "pkg:hex/tiny_lib",
             "defaultStatus" => "unaffected",
             "versions" => [
               %{
                 "version" => "1.0.0",
                 "lessThan" => "1.0.1",
                 "status" => "affected",
                 "versionType" => "semver"
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0005.html", ["vendor-advisory"])
         ]
       }},

      # 6 — vendor/product only, no packageURL (imported-style), CRITICAL with
      # the longest CVSS4 vector (overflow test), long title (band wrap test).
      {"CVE-2098-0006", "2026-03-01T10:00:00.000Z",
       %{
         "title" =>
           "Improper Neutralization of Special Elements used in an OS Command in the legacy provisioning bridge shipped alongside embedded gateway firmware images",
         "descriptions" => prose("A shell metacharacter reaches `os:cmd/1` unsanitized."),
         "problemTypes" => [
           cwe(
             "CWE-78",
             "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
           )
         ],
         "impacts" => [capec_restated("CAPEC-88", "OS Command Injection")],
         "metrics" => [cvss4(@critical_vector, 9.4, "CRITICAL")],
         "affected" => [
           %{
             "vendor" => "Legacy Gateway Corp.",
             "product" => "provisioning-bridge",
             "defaultStatus" => "affected",
             "versions" => [
               %{
                 "version" => "2.0",
                 "lessThanOrEqual" => "2.9",
                 "status" => "affected",
                 "versionType" => "custom"
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0006.html", ["vendor-advisory"]),
           ref(
             "https://example.com/a-very-long-writeup-url-that-should-not-break-the-references-card-layout-even-when-it-is-unreasonably-long-because-real-links-are/2026/03/analysis.html",
             ["exploit"]
           )
         ]
       }},

      # 7 — all-versions-affected: defaultStatus affected, NO versions[].
      {"CVE-2098-0007", "2026-03-08T10:00:00.000Z",
       %{
         "title" => "Hard-coded API token in mix task template",
         "descriptions" => prose("Every released version embeds the same publishing token."),
         "problemTypes" => [cwe("CWE-798", "Use of Hard-coded Credentials")],
         "metrics" => [cvss4(@medium_vector, 7.1, "HIGH")],
         "affected" => [
           %{
             "vendor" => "acme",
             "product" => "release_tools",
             "packageURL" => "pkg:hex/release_tools",
             "defaultStatus" => "affected"
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0007.html", ["vendor-advisory"])
         ]
       }},

      # 8 — many references, every tag the renderer knows + untagged + long
      # list (10+): ordering + tag pills at scale.
      {"CVE-2098-0008", "2026-03-15T10:00:00.000Z",
       %{
         "title" => "Header smuggling via duplicated Transfer-Encoding in proxy_lib",
         "descriptions" => prose("Downstream and upstream disagree on the second Transfer-Encoding header."),
         "problemTypes" => [
           cwe(
             "CWE-444",
             "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')"
           )
         ],
         "impacts" => [
           capec_prose(
             "CAPEC-33",
             "Chained proxies can be desynchronized to smuggle a second request past access controls."
           )
         ],
         "metrics" => [cvss4(@medium_vector, 6.3, "MEDIUM")],
         "affected" => [
           %{
             "vendor" => "acme",
             "product" => "proxy_lib",
             "packageURL" => "pkg:hex/proxy_lib",
             "defaultStatus" => "unaffected",
             "versions" => [
               %{
                 "version" => "0.2.0",
                 "lessThan" => "0.8.4",
                 "status" => "affected",
                 "versionType" => "semver",
                 "changes" => [%{"at" => "0.8.4", "status" => "unaffected"}]
               }
             ]
           }
         ],
         "references" => [
           ref("https://example.com/mirror-writeup", ["third-party-advisory"]),
           ref("https://cna.erlef.org/cves/CVE-2098-0008.html", ["vendor-advisory"]),
           ref(
             "https://github.com/acme/proxy_lib/commit/00aa11bb22cc33dd44ee55ff66aa77bb88cc99dd",
             ["patch"]
           ),
           ref(
             "https://github.com/acme/proxy_lib/commit/11bb22cc33dd44ee55ff66aa77bb88cc99dd00aa",
             ["patch"]
           ),
           ref("https://example.com/poc", ["exploit"]),
           ref("https://example.com/dead-mirror", ["broken-link"]),
           ref("https://osv.dev/vulnerability/EEF-CVE-2098-0008", ["related"]),
           ref("https://example.com/background-reading", ["technical-description"]),
           ref("https://example.com/vendor-faq", []),
           ref("https://example.com/mailing-list-thread", ["mailing-list"]),
           ref("https://example.com/registry-note", ["product"])
         ]
       }},

      # 9 — five packages (checker select variant) mixing semver + one
      # git-only package (excluded from checker) + duplicate-id test.
      {"CVE-2098-0009", "2026-04-01T10:00:00.000Z",
       %{
         "title" => "Shared parser pool poisoning across umbrella packages",
         "descriptions" => prose("A poisoned parser state leaks across the five umbrella packages."),
         "problemTypes" => [cwe("CWE-665", "Improper Initialization")],
         "metrics" => [cvss4(@medium_vector, 4.8, "MEDIUM")],
         "affected" =>
           for {name, fix} <- [
                 {"umbrella_core", "2.1.0"},
                 {"umbrella_web", "1.9.2"},
                 {"umbrella_json", "3.0.1"},
                 {"umbrella_xml", "0.7.7"}
               ] do
             %{
               "vendor" => "umbrella",
               "product" => name,
               "packageURL" => "pkg:hex/#{name}",
               "defaultStatus" => "unaffected",
               "versions" => [
                 %{
                   "version" => "0.1.0",
                   "lessThan" => fix,
                   "status" => "affected",
                   "versionType" => "semver",
                   "changes" => [%{"at" => fix, "status" => "unaffected"}]
                 }
               ]
             }
           end ++
             [
               %{
                 "vendor" => "umbrella",
                 "product" => "umbrella_native",
                 "packageURL" => "pkg:github/umbrella/umbrella_native",
                 "repo" => "https://github.com/umbrella/umbrella_native",
                 "defaultStatus" => "unaffected",
                 "versions" => [
                   %{
                     "version" => "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00",
                     "lessThan" => "*",
                     "status" => "affected",
                     "versionType" => "git"
                   }
                 ]
               }
             ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0009.html", ["vendor-advisory"])
         ]
       }},

      # 10 — OTP multi-branch with backports: several bounded otp ranges with
      # branch labels + wide intro bound (maint-label vs 17.4-style question).
      {"CVE-2098-0010", "2026-04-20T10:00:00.000Z",
       %{
         "title" => "inets httpd path traversal on Windows UNC paths",
         "descriptions" => prose("Backslash-separated traversal sequences bypass the sanitizer on Windows."),
         "problemTypes" => [
           cwe(
             "CWE-22",
             "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
           )
         ],
         "impacts" => [capec_restated("CAPEC-126", "Path Traversal")],
         "metrics" => [cvss4(@medium_vector, 8.2, "HIGH")],
         "affected" => [
           %{
             "vendor" => "Erlang",
             "product" => "OTP",
             "packageName" => "inets",
             "packageURL" => "pkg:otp/inets?repository_url=https%3A%2F%2Fgithub.com%2Ferlang%2Fotp",
             "repo" => "https://github.com/erlang/otp",
             "cpes" => ["cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*"],
             "defaultStatus" => "unaffected",
             "modules" => ["httpd"],
             "programFiles" => ["lib/inets/src/http_server/httpd_request.erl"],
             "versions" => [
               %{
                 "version" => "17.4",
                 "lessThan" => "26.2.5.16",
                 "status" => "affected",
                 "versionType" => "otp",
                 "changes" => [%{"at" => "26.2.5.16", "status" => "unaffected"}]
               },
               %{
                 "version" => "27.0",
                 "lessThan" => "27.3.4.13",
                 "status" => "affected",
                 "versionType" => "otp",
                 "changes" => [%{"at" => "27.3.4.13", "status" => "unaffected"}]
               },
               %{
                 "version" => "28.0",
                 "lessThan" => "28.5.0.2",
                 "status" => "affected",
                 "versionType" => "otp",
                 "changes" => [%{"at" => "28.5.0.2", "status" => "unaffected"}]
               },
               %{
                 "version" => "be95772ee1fcfe71045ef070130bea7a910b81e3",
                 "lessThan" => "*",
                 "status" => "affected",
                 "versionType" => "git",
                 "changes" => [
                   %{
                     "at" => "2691a806231ffd0490a8a9e20500dec0c7e73727",
                     "status" => "unaffected"
                   },
                   %{"at" => "521bcfa24407ee8cb5614823cf905c37ea3aa605", "status" => "unaffected"}
                 ]
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0010.html", ["vendor-advisory"]),
           ref("https://github.com/erlang/otp/commit/2691a806231ffd0490a8a9e20500dec0c7e73727", [
             "patch"
           ])
         ],
         "credits" => [
           %{"lang" => "en", "type" => "finder", "value" => "Windows Server operator"}
         ]
       }},

      # 11 — CWE whose id has no catalog entry locally (chip id-only fallback)
      # + CAPEC likewise; also unicode in title/description.
      {"CVE-2098-0011", "2026-05-05T10:00:00.000Z",
       %{
         "title" => "Zøl parser panics on überlong UTF-8 sequences",
         "descriptions" => prose("Süß crafted multibyte input (\"🦀\") crashes the NIF-backed parser."),
         "problemTypes" => [cwe("CWE-99999", "Nonexistent Demo Weakness")],
         "impacts" => [capec_restated("CAPEC-99999", "Nonexistent Demo Pattern")],
         "metrics" => [cvss4(@medium_vector, 3.1, "LOW")],
         "affected" => [
           %{
             "vendor" => "acme",
             "product" => "zoel_parser",
             "packageURL" => "pkg:hex/zoel_parser",
             "defaultStatus" => "unaffected",
             "versions" => [
               %{
                 "version" => "0.3.0",
                 "lessThan" => "0.6.2",
                 "status" => "affected",
                 "versionType" => "semver",
                 "changes" => [%{"at" => "0.6.2", "status" => "unaffected"}]
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0011.html", ["vendor-advisory"])
         ]
       }},

      # 12 — NONE score (0.0) + timeline + datePublic: the grey chip case.
      {"CVE-2098-0012", "2026-05-20T10:00:00.000Z",
       %{
         "title" => "Docs-only advisory: misleading example enabled debug logging",
         "descriptions" => prose("No code defect; the README example shipped with debug logging of secrets."),
         "problemTypes" => [cwe("CWE-532", "Insertion of Sensitive Information into Log File")],
         "metrics" => [
           cvss4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "NONE")
         ],
         "affected" => [
           %{
             "vendor" => "acme",
             "product" => "logger_helpers",
             "packageURL" => "pkg:hex/logger_helpers",
             "defaultStatus" => "unaffected",
             "versions" => [
               %{
                 "version" => "1.0.0",
                 "lessThan" => "1.4.0",
                 "status" => "affected",
                 "versionType" => "semver",
                 "changes" => [%{"at" => "1.4.0", "status" => "unaffected"}]
               }
             ]
           }
         ],
         "references" => [
           ref("https://cna.erlef.org/cves/CVE-2098-0012.html", ["vendor-advisory"])
         ]
       }}
    ]
  end
end

DevSeed.PublicCveMatrix.run()
