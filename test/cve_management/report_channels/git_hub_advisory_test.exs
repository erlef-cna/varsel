# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisoryTest do
  use CveManagement.DataCase, async: false

  alias CveManagement.Accounts.GitHubAppToken
  alias CveManagement.CWE.Weakness
  alias CveManagement.GitHub.AdvisoryClient
  alias CveManagement.ReportChannels.GitHubAdvisory

  @advisory_json %{
    "ghsa_id" => "GHSA-1234-5678-abcd",
    "cve_id" => "CVE-2026-1234",
    "summary" => "Test vulnerability",
    "description" => "A test vulnerability description.",
    "severity" => "high",
    "state" => "draft",
    "url" => "https://api.github.com/repos/erlef/test/security-advisories/GHSA-1234-5678-abcd",
    "html_url" => "https://github.com/erlef/test/security-advisories/GHSA-1234-5678-abcd",
    "author" => %{
      "login" => "octocat",
      "html_url" => "https://github.com/octocat",
      "avatar_url" => "https://github.com/octocat.png",
      "events_url" => "https://api.github.com/users/octocat/events"
    },
    "publisher" => nil,
    "created_at" => "2026-01-01T00:00:00Z",
    "updated_at" => "2026-01-02T00:00:00Z",
    "published_at" => nil,
    "closed_at" => nil,
    "withdrawn_at" => nil,
    "vulnerabilities" => [
      %{
        "package" => %{"ecosystem" => "Erlang", "name" => "test_lib"},
        "vulnerable_version_range" => "< 1.2.3",
        "patched_versions" => "1.2.3",
        "vulnerable_functions" => []
      }
    ],
    "cvss_severities" => %{
      "cvss_v3" => %{
        "vector_string" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score" => 9.8
      },
      "cvss_v4" => nil
    },
    "cwe_ids" => ["CWE-79", "CWE-89"],
    "identifiers" => [%{"type" => "GHSA", "value" => "GHSA-1234-5678-abcd"}],
    "credits" => [%{"login" => "researcher", "type" => "reporter"}],
    "credits_detailed" => [],
    "collaborating_users" => [
      %{
        "login" => "collab",
        "html_url" => "https://github.com/collab",
        "avatar_url" => nil,
        "events_url" => "https://api.github.com/users/collab/events"
      }
    ],
    "collaborating_teams" => [],
    "submission" => nil,
    "private_fork" => nil
  }

  defp create_user(handle \\ nil) do
    handle = handle || "user#{System.unique_integer([:positive])}"

    CveManagement.Accounts.User
    |> Ash.Changeset.for_create(
      :register_with_github,
      %{
        user_info: %{
          "sub" => System.unique_integer([:positive]),
          "preferred_username" => handle,
          "name" => "Test User",
          "email" => "#{handle}@example.com"
        },
        oauth_tokens: %{"access_token" => "gho_test"}
      },
      authorize?: false
    )
    |> Ash.create!(authorize?: false)
  end

  defp create_token(user) do
    GitHubAppToken
    |> Ash.Changeset.for_create(:upsert_from_oauth, %{
      user_id: user.id,
      access_token: "ghu_test_access",
      refresh_token: "ghr_test_refresh",
      expires_at: ~U[2030-01-01 00:00:00Z]
    })
    |> Ash.create!(authorize?: false)
  end

  defp ingest(user, json \\ @advisory_json) do
    GitHubAdvisory
    |> Ash.Changeset.for_create(:ingest_json, %{fetched_by_user_id: user.id, raw_data: json}, authorize?: false)
    |> Ash.create!(authorize?: false)
  end

  defp stub_advisory(body) do
    Req.Test.stub(AdvisoryClient, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, Jason.encode!(body))
    end)
  end

  describe "ingest_json" do
    test "creates an advisory from raw JSON" do
      user = create_user()
      advisory = ingest(user)

      assert advisory.ghsa_id == "GHSA-1234-5678-abcd"
      assert advisory.cve_id == "CVE-2026-1234"
      assert advisory.state == :draft
      assert advisory.severity == :high
      assert advisory.fetched_by_user_id == user.id
    end

    test "strips extra fields from github user objects" do
      user = create_user()
      advisory = ingest(user)

      assert advisory.author.login == "octocat"
      assert advisory.author.html_url == "https://github.com/octocat"
      refute Map.has_key?(advisory.author, :events_url)
    end

    test "strips extra fields from collaborating_users" do
      user = create_user()
      advisory = ingest(user)

      assert [%{login: "collab"}] = advisory.collaborating_users
    end

    test "parses cvss_severities vector string" do
      user = create_user()
      advisory = ingest(user)

      assert advisory.cvss_severities.cvss_v3.vector ==
               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

      assert advisory.cvss_severities.cvss_v3.score == 9.8
      assert advisory.cvss_severities.cvss_v4 == nil
    end

    test "associates CWE weaknesses via cwe_ids" do
      # seed CWE weaknesses
      Ash.create!(
        Weakness,
        %{cwe_id: 79, name: "XSS", status: :draft, abstraction: :base, description: "XSS"},
        action: :upsert,
        authorize?: false
      )

      Ash.create!(
        Weakness,
        %{cwe_id: 89, name: "SQLi", status: :draft, abstraction: :base, description: "SQLi"},
        action: :upsert,
        authorize?: false
      )

      user = create_user()
      advisory = ingest(user)
      loaded = Ash.load!(advisory, [:weaknesses], authorize?: false)

      assert length(loaded.weaknesses) == 2
      assert Enum.any?(loaded.weaknesses, &(&1.cwe_id == 79))
      assert Enum.any?(loaded.weaknesses, &(&1.cwe_id == 89))
    end

    test "upserts on re-ingest" do
      user = create_user()
      ingest(user)

      updated = Map.put(@advisory_json, "summary", "Updated summary")
      ingest(user, updated)

      assert Ash.count!(GitHubAdvisory, authorize?: false) == 1
      [advisory] = Ash.read!(GitHubAdvisory, authorize?: false)
      assert advisory.summary == "Updated summary"
    end
  end

  describe "ingest_url" do
    test "fetches the URL and ingests the advisory" do
      user = create_user()
      create_token(user)
      stub_advisory(@advisory_json)

      advisory =
        GitHubAdvisory
        |> Ash.Changeset.for_create(
          :ingest_url,
          %{
            fetched_by_user_id: user.id,
            url: "https://api.github.com/repos/erlef/test/security-advisories/GHSA-1234-5678-abcd"
          },
          authorize?: false
        )
        |> Ash.create!(authorize?: false)

      assert advisory.ghsa_id == "GHSA-1234-5678-abcd"
    end
  end

  describe "refresh" do
    test "re-fetches and updates the advisory" do
      user = create_user()
      create_token(user)
      advisory = ingest(user)

      updated_json = Map.put(@advisory_json, "summary", "Refreshed summary")
      stub_advisory(updated_json)

      refreshed =
        advisory
        |> Ash.Changeset.for_update(:refresh, %{}, authorize?: false)
        |> Ash.update!(authorize?: false)

      assert refreshed.summary == "Refreshed summary"
    end
  end

  describe "read policy" do
    test "fetching user can read their own advisories" do
      user = create_user()
      ingest(user)

      assert {:ok, [_]} = Ash.read(GitHubAdvisory, actor: user)
    end

    test "other user cannot read someone else's advisory" do
      user = create_user()
      other = create_user()
      ingest(user)

      assert {:ok, []} = Ash.read(GitHubAdvisory, actor: other)
    end

    test "collaborating user can read advisory" do
      user = create_user()
      collab = create_user("collab")
      ingest(user)

      assert {:ok, [_]} = Ash.read(GitHubAdvisory, actor: collab)
    end

    test "poc can read all advisories" do
      poc = create_user()
      poc = Ash.update!(poc, %{role: :poc}, action: :update, authorize?: false)
      user = create_user()
      ingest(user)

      assert {:ok, [_]} = Ash.read(GitHubAdvisory, actor: poc)
    end
  end
end
