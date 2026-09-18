# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryTest do
  use ExUnit.Case, async: true

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Varsel.Cases.GitHubAdvisory

  test "summary/1 names the advisory, its repository and its standing" do
    assert GitHubAdvisory.summary(otp_advisory()) == %{
             ghsa_id: "GHSA-pwvh-c689-f8q5",
             cve_id: "CVE-2026-48858",
             state: :published,
             html_url: "https://github.com/erlang/otp/security/advisories/GHSA-pwvh-c689-f8q5",
             title: "Unbounded resource use in inets",
             owner: "erlang",
             repo: "otp",
             collaborators: ["garazdawi"],
             teams: []
           }
  end

  test "a global database entry belongs to no repository" do
    advisory = %{
      "ghsa_id" => "GHSA-pwvh-c689-f8q5",
      "html_url" => "https://github.com/advisories/GHSA-pwvh-c689-f8q5"
    }

    assert GitHubAdvisory.repository(advisory) == nil
    assert GitHubAdvisory.repo_url(advisory) == nil
    assert %{owner: nil, repo: nil, state: :unknown} = GitHubAdvisory.summary(advisory)
  end

  test "repo_url/1 is the repository's page" do
    assert GitHubAdvisory.repo_url(hex_advisory()) == "https://github.com/acme/acme_lib"
  end

  test "state/1 knows GitHub's states and nothing else" do
    assert GitHubAdvisory.state("draft") == :draft
    assert GitHubAdvisory.state("triage") == :triage
    assert GitHubAdvisory.state("something new") == :unknown
    assert GitHubAdvisory.state(nil) == :unknown
  end

  test "time/1 reads GitHub's timestamps in whole seconds" do
    assert GitHubAdvisory.time("2026-08-20T09:00:00.123Z") == ~U[2026-08-20 09:00:00Z]
    assert GitHubAdvisory.time("not a time") == nil
    assert GitHubAdvisory.time(nil) == nil
  end
end
