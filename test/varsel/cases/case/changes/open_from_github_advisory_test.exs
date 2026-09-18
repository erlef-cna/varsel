# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.OpenFromGitHubAdvisoryTest do
  @moduledoc """
  Opening a case from a GitHub advisory: how the advisory is read, what the
  case carries over, the children it creates, and who may do it.
  """

  use Varsel.DataCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi

  @hex_url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"
  @otp_url "https://github.com/erlang/otp/security/advisories/GHSA-pwvh-c689-f8q5"
  @elixir_url "https://github.com/elixir-lang/elixir/security/advisories/GHSA-2cfg-hjmp-qrvw"

  @loads [
    :weaknesses,
    :credits,
    :references,
    assignments: [],
    affected_packages: [channels: []]
  ]

  setup do
    Fixtures.seed_weakness(113, "Improper Neutralization of CRLF Sequences in HTTP Headers")

    %{
      poc: Fixtures.register_user("advisory_poc", :poc),
      supporter: Fixtures.register_user("advisory_supporter", :supporter)
    }
  end

  # GitHub answering the advisory read at `path` with `advisory`, telling
  # the test how it was asked, and profile lookups with the name in
  # `profiles` for that login.
  defp stub_advisory(path, advisory, profiles \\ %{}) do
    test_pid = self()

    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["users", login] ->
          Req.Test.json(conn, %{"login" => login, "name" => profiles[login], "email" => nil})

        _advisory ->
          send(
            test_pid,
            {:github, conn.request_path, Plug.Conn.get_req_header(conn, "authorization")}
          )

          assert conn.request_path == path
          Req.Test.json(conn, advisory)
      end
    end)
  end

  defp stub_github_unreachable do
    GitHubApi.stub(fn _conn -> flunk("GitHub was contacted before the caller was refused") end)
  end

  defp open(actor, url \\ @hex_url) do
    Cases.open_case_from_github_advisory(%{advisory_url: url}, actor: actor, load: @loads)
  end

  test "reads the advisory as the caller and fills the case from it", %{poc: poc} do
    stub_advisory("/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw", hex_advisory())

    assert {:ok, case_record} = open(poc)

    assert_received {:github, _path, ["Bearer gho_token"]}

    assert case_record.state == :draft
    assert case_record.title == "Header injection in acme_lib"
    assert case_record.description_md == "acme_lib passes user input into response headers."
    assert case_record.cvss_v4 == nil
    assert case_record.date_public == nil
    assert Enum.map(case_record.assignments, & &1.user_id) == [poc.id]
  end

  test "creates the classification and credits, and leads the references with the advisory", %{
    poc: poc
  } do
    alice = Fixtures.register_user("alice")
    stub_advisory("/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw", hex_advisory())

    {:ok, case_record} = open(poc)

    assert Enum.map(case_record.weaknesses, & &1.cwe_id) == [113]

    assert [%{name: "alice name", credit_type: :finder, position: 0, user_id: user_id}] =
             case_record.credits

    assert user_id == alice.id

    assert case_record.references == []

    assert [%{url: @hex_url, tags: ["vendor-advisory", "related"]} | _rest] =
             Cases.get_case!(case_record.id, actor: poc, load: [:derived_references]).derived_references
  end

  test "creates each affected package with its channels and no boundaries", %{poc: poc} do
    stub_advisory("/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw", hex_advisory())

    {:ok, case_record} = open(poc)

    assert [package] = case_record.affected_packages
    assert package.vendor == "acme"
    assert package.product == "acme_lib"
    assert to_string(package.repo_url) == "https://github.com/acme/acme_lib"

    assert package.channels |> Enum.map(&{&1.purl_type, &1.name}) |> Enum.sort() ==
             [{"github", "acme_lib"}, {"hex", "acme_lib"}]

    assert Cases.list_version_events!(actor: poc) == []
  end

  test "an erlang/otp advisory goes through the OTP preset with its applications", %{poc: poc} do
    Fixtures.seed_weakness(770, "Allocation of Resources Without Limits or Throttling")

    stub_advisory(
      "/repos/erlang/otp/security-advisories/GHSA-pwvh-c689-f8q5",
      otp_advisory(),
      %{"garazdawi" => "Lukas Larsson"}
    )

    {:ok, case_record} = open(poc, @otp_url)

    assert case_record.cvss_v4.vector ==
             "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"

    assert case_record.date_public == ~U[2026-08-20 09:00:00Z]

    assert [package] = case_record.affected_packages
    assert {package.vendor, package.product} == {"Erlang", "OTP"}

    assert package.channels |> Enum.map(&{&1.purl_type, &1.name}) |> Enum.sort() ==
             [{"github", "otp"}, {"otp", "inets"}, {"software-id", "otp"}]

    # Declined credits are dropped and pending ones stay. A person without an
    # account here is named as their GitHub profile is, or by login.
    assert Enum.map(case_record.credits, &{&1.name, &1.credit_type}) ==
             [{"Lukas Larsson", :reporter}, {"Whaileee", :remediation_reviewer}]
  end

  test "an elixir-lang/elixir advisory spells its applications as the preset does", %{poc: poc} do
    advisory =
      hex_advisory()
      |> Map.put("html_url", @elixir_url)
      |> Map.put("vulnerabilities", [
        %{
          "package" => %{"ecosystem" => "erlang", "name" => "elixir"},
          "vulnerable_version_range" => "< 1.18"
        },
        %{
          "package" => %{"ecosystem" => "elixir", "name" => "ExUnit"},
          "vulnerable_version_range" => "< 1.18"
        }
      ])

    stub_advisory("/repos/elixir-lang/elixir/security-advisories/GHSA-2cfg-hjmp-qrvw", advisory)

    {:ok, case_record} = open(poc, @elixir_url)

    assert [package] = case_record.affected_packages
    assert {package.vendor, package.product} == {"elixir-lang", "elixir"}

    assert package.channels |> Enum.map(&{&1.purl_type, &1.name}) |> Enum.sort() ==
             [{"github", "elixir"}, {"otp", "ex_unit"}]
  end

  test "a CWE the catalog does not know is left out", %{poc: poc} do
    advisory = Map.put(hex_advisory(), "cwe_ids", ["CWE-113", "CWE-999999"])
    stub_advisory("/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw", advisory)

    {:ok, case_record} = open(poc)

    assert Enum.map(case_record.weaknesses, & &1.cwe_id) == [113]
  end

  test "a bare GHSA id reads the global database entry", %{poc: poc} do
    global =
      hex_advisory()
      |> Map.put("html_url", "https://github.com/advisories/GHSA-2cfg-hjmp-qrvw")
      |> Map.put("source_code_location", "https://github.com/acme/acme_lib")

    stub_advisory("/advisories/GHSA-2cfg-hjmp-qrvw", global)

    {:ok, case_record} = open(poc, "GHSA-2cfg-hjmp-qrvw")

    assert [%{repo_url: repo_url, vendor: "acme"}] = case_record.affected_packages
    assert to_string(repo_url) == "https://github.com/acme/acme_lib"

    assert [%{url: "https://github.com/advisories/GHSA-2cfg-hjmp-qrvw"} | _rest] =
             Cases.get_case!(case_record.id, actor: poc, load: [:derived_references]).derived_references
  end

  test "an address that is no advisory is refused before GitHub is asked", %{poc: poc} do
    stub_github_unreachable()

    assert {:error, %Invalid{errors: [error]}} = open(poc, "https://github.com/acme/acme_lib")

    assert error.field == :advisory_url
    assert error.message =~ "is not a GitHub advisory URL"
  end

  test "an advisory GitHub does not show the caller opens nothing", %{poc: poc} do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 404, ~s({"message":"Not Found"})))

    assert {:error, %Invalid{errors: [error]}} = open(poc)

    assert error.message =~ "names no advisory you can see"
    assert Cases.list_cases!(actor: poc) == []
  end

  test "a credit GitHub does not know takes the case down with it", %{poc: poc} do
    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["users", _login] -> Plug.Conn.send_resp(conn, 404, "{}")
        _advisory -> Req.Test.json(conn, hex_advisory())
      end
    end)

    assert {:error, %Invalid{errors: [error]}} = open(poc)

    assert error.field == :handles
    assert error.message =~ "alice is not a GitHub account"
    assert Cases.list_cases!(actor: poc) == []
  end

  test "a supporter opens a case and is on it", %{supporter: supporter} do
    stub_advisory("/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw", hex_advisory())

    assert {:ok, case_record} = open(supporter)
    assert Enum.map(case_record.assignments, & &1.user_id) == [supporter.id]
    assert [%{name: "alice"}] = case_record.credits
    assert [_package] = case_record.affected_packages
  end

  test "a signed-in person without a role is refused before GitHub is asked" do
    stub_github_unreachable()
    nobody = Fixtures.register_user("advisory_nobody")

    assert {:error, %Forbidden{}} = open(nobody)
  end

  test "nobody signed in is refused before GitHub is asked" do
    stub_github_unreachable()

    assert {:error, %Forbidden{}} = open(nil)
  end
end
