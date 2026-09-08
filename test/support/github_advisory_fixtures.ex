# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.GitHubAdvisoryFixtures do
  @moduledoc """
  GitHub security advisories as the REST API returns them, trimmed to the
  fields the mapping reads.

  `otp_advisory/0` is GHSA-pwvh-c689-f8q5 on erlang/otp as fetched on
  2026-09-05: a real example of the free-text `ecosystem` (`""` for the
  release, `otp` for an application) and of several fixed maintenance lines.
  `hex_advisory/0` is a made-up advisory on a hex package.
  """

  @doc "A published erlang/otp advisory with an OTP application entry and the release entry."
  def otp_advisory do
    %{
      "ghsa_id" => "GHSA-pwvh-c689-f8q5",
      "cve_id" => "CVE-2026-48858",
      "html_url" => "https://github.com/erlang/otp/security/advisories/GHSA-pwvh-c689-f8q5",
      "state" => "published",
      "severity" => "high",
      "summary" => "Unbounded resource use in inets",
      "description" => "The inets HTTP server allocates without limit.\r\n\r\nUpgrade.",
      "published_at" => "2026-08-20T09:00:00Z",
      "updated_at" => "2026-08-21T10:00:00Z",
      "withdrawn_at" => nil,
      "cvss" => %{"score" => nil, "vector_string" => nil},
      "cvss_severities" => %{
        "cvss_v3" => %{"score" => nil, "vector_string" => nil},
        "cvss_v4" => %{
          "score" => 8.7,
          "vector_string" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
        }
      },
      "cwe_ids" => ["CWE-770"],
      "cwes" => [
        %{"cwe_id" => "CWE-770", "name" => "Allocation of Resources Without Limits or Throttling"}
      ],
      "credits" => [
        %{"login" => "garazdawi", "type" => "reporter"},
        %{"login" => "Whaileee", "type" => "remediation_reviewer"}
      ],
      "credits_detailed" => [
        %{
          "state" => "accepted",
          "type" => "reporter",
          "user" => %{"login" => "garazdawi", "id" => 111_762}
        },
        %{
          "state" => "pending",
          "type" => "remediation_reviewer",
          "user" => %{"login" => "Whaileee", "id" => 76_457_941}
        },
        %{"state" => "declined", "type" => "finder", "user" => %{"login" => "nobody", "id" => 1}}
      ],
      "collaborating_users" => [%{"login" => "garazdawi"}],
      "collaborating_teams" => nil,
      "vulnerabilities" => [
        %{
          "package" => %{"ecosystem" => "", "name" => "OTP"},
          "patched_versions" => "29.0.6, 28.5.0.6, 27.3.4.17",
          "vulnerable_functions" => [],
          "vulnerable_version_range" => ">= 17.0"
        },
        %{
          "package" => %{"ecosystem" => "otp", "name" => "inets"},
          "patched_versions" => "9.7.2, 9.6.2.3, 9.3.2.7",
          "vulnerable_functions" => [],
          "vulnerable_version_range" => ">= 5.10"
        }
      ]
    }
  end

  @doc "A draft advisory on a hex package, one erlang entry, no CVSS."
  def hex_advisory do
    %{
      "ghsa_id" => "GHSA-2cfg-hjmp-qrvw",
      "cve_id" => nil,
      "html_url" => "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw",
      "state" => "draft",
      "severity" => "medium",
      "summary" => "Header injection in acme_lib",
      "description" => "acme_lib passes user input into response headers.",
      "published_at" => nil,
      "updated_at" => "2026-09-01T12:00:00Z",
      "withdrawn_at" => nil,
      "cvss_severities" => %{
        "cvss_v3" => %{
          "score" => 5.3,
          "vector_string" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
        },
        "cvss_v4" => %{"score" => nil, "vector_string" => nil}
      },
      "cwe_ids" => ["CWE-113", "CWE-113"],
      "credits" => [%{"login" => "alice", "type" => "finder"}],
      "credits_detailed" => [
        %{"state" => "accepted", "type" => "finder", "user" => %{"login" => "alice", "id" => 2}}
      ],
      "collaborating_users" => [],
      "vulnerabilities" => [
        %{
          "package" => %{"ecosystem" => "erlang", "name" => "acme_lib"},
          "patched_versions" => "1.2.3",
          "vulnerable_functions" => [],
          "vulnerable_version_range" => ">=1.0.0,<1.2.3"
        }
      ]
    }
  end
end
