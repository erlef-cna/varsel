# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLinkTest do
  @moduledoc """
  Linking a case to a GitHub advisory: what the link stores, the reference it
  adds, how it is refreshed and removed, what a pull takes onto the case and
  a push writes to GitHub, and who may do each.
  """

  use Varsel.DataCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi

  @hex_url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"
  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"

  setup do
    poc = Fixtures.register_user("link_poc", :poc)
    GitHubApi.stub_advisory(hex_advisory())

    %{poc: poc, case: Fixtures.open_case(poc, %{title: "Header injection in acme_lib"})}
  end

  defp link!(case_record, actor, url \\ @hex_url) do
    Cases.link_github_advisory!(%{case_id: case_record.id, advisory_url: url}, actor: actor)
  end

  defp link(case_record, actor, url \\ @hex_url) do
    Cases.link_github_advisory(%{case_id: case_record.id, advisory_url: url}, actor: actor)
  end

  defp references(case_record, actor) do
    Cases.get_case!(case_record.id, actor: actor, load: [:references]).references
  end

  defp derived_references(case_record, actor) do
    Cases.get_case!(case_record.id, actor: actor, load: [:derived_references]).derived_references
  end

  defp approve!(case_record, poc) do
    case_record |> Cases.request_case_review!(actor: poc) |> Cases.approve_case!(actor: poc)
  end

  defp stub_github_unreachable do
    GitHubApi.stub(fn _conn -> flunk("GitHub was contacted before the caller was refused") end)
  end

  test "links the advisory, which leads the rendered references without being stored", %{
    poc: poc,
    case: case_record
  } do
    link = link!(case_record, poc)

    assert link.ghsa_id == "GHSA-2cfg-hjmp-qrvw"
    assert {link.owner, link.repo} == {"acme", "acme_lib"}
    assert link.state == :draft
    assert link.title == "Header injection in acme_lib"
    assert link.cve_id == nil
    assert link.advisory["summary"] == "Header injection in acme_lib"
    assert DateTime.diff(DateTime.utc_now(), link.fetched_at) < 5

    assert references(case_record, poc) == []

    assert [%{url: @hex_url, tags: ["vendor-advisory", "related"]} | _rest] =
             derived_references(case_record, poc)
  end

  test "a stored reference carrying the advisory stays the stored one", %{
    poc: poc,
    case: case_record
  } do
    Cases.add_case_reference!(
      %{case_id: case_record.id, url: @hex_url, tags: ["vendor-advisory"]},
      actor: poc
    )

    link!(case_record, poc)

    assert [%{tags: ["vendor-advisory"]}] = references(case_record, poc)
    refute Enum.any?(derived_references(case_record, poc), &(&1.url == @hex_url))
  end

  test "one advisory per case, one case per advisory", %{poc: poc, case: case_record} do
    link!(case_record, poc)

    assert {:error, %Invalid{errors: [%{field: :advisory_url}]}} = link(case_record, poc)

    other = Fixtures.open_case(poc, %{title: "Another case"})

    assert {:error, %Invalid{errors: [%{field: :advisory_url}]}} = link(other, poc)
  end

  test "a bare GHSA id links the global database entry and refreshes it there", %{
    poc: poc,
    case: case_record
  } do
    test_pid = self()

    GitHubApi.stub(fn conn ->
      send(test_pid, {:github, conn.request_path})

      Req.Test.json(
        conn,
        Map.put(hex_advisory(), "html_url", "https://github.com/advisories/GHSA-2cfg-hjmp-qrvw")
      )
    end)

    link = link!(case_record, poc, "GHSA-2cfg-hjmp-qrvw")

    assert_received {:github, "/advisories/GHSA-2cfg-hjmp-qrvw"}
    assert {link.owner, link.repo} == {nil, nil}
    assert to_string(link.html_url) == "https://github.com/advisories/GHSA-2cfg-hjmp-qrvw"

    assert %GitHubAdvisoryLink{} = Cases.refresh_github_advisory_link!(link, actor: poc)
    assert_received {:github, "/advisories/GHSA-2cfg-hjmp-qrvw"}
  end

  test "an address GitHub does not answer links nothing", %{poc: poc, case: case_record} do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 404, "{}"))

    assert {:error, %Invalid{errors: [%{field: :advisory_url}]}} = link(case_record, poc)
    assert references(case_record, poc) == []
  end

  test "an address that is no advisory links nothing", %{poc: poc, case: case_record} do
    stub_github_unreachable()

    assert {:error, %Invalid{errors: [%{field: :advisory_url, message: message}]}} =
             link(case_record, poc, "https://example.com/advisories/GHSA-2cfg-hjmp-qrvw")

    assert message == "is not a GitHub advisory URL or GHSA id"
  end

  test "refresh reads the advisory again and stores what GitHub now says", %{
    poc: poc,
    case: case_record
  } do
    link = link!(case_record, poc)

    GitHubApi.stub(fn conn ->
      assert conn.request_path == "/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw"

      Req.Test.json(
        conn,
        hex_advisory()
        |> Map.put("state", "published")
        |> Map.put("cve_id", "CVE-2026-1234")
        |> Map.put("summary", "Header injection in acme_lib (published)")
      )
    end)

    refreshed = Cases.refresh_github_advisory_link!(link, actor: poc)

    assert refreshed.state == :published
    assert refreshed.cve_id == "CVE-2026-1234"
    assert refreshed.title == "Header injection in acme_lib (published)"
    assert refreshed.advisory["state"] == "published"
  end

  test "unlink removes the link and with it the derived reference", %{poc: poc, case: case_record} do
    link = link!(case_record, poc)

    assert :ok = Cases.unlink_github_advisory(link, actor: poc)

    assert Cases.get_case!(case_record.id, actor: poc, load: [:github_advisory_link]).github_advisory_link ==
             nil

    refute Enum.any?(derived_references(case_record, poc), &(&1.url == @hex_url))
  end

  describe "pull" do
    setup %{poc: poc, case: case_record} do
      Fixtures.seed_weakness(113, "Improper Neutralization of CRLF Sequences in HTTP Headers")
      alice = Fixtures.register_user("alice")

      %{link: link!(case_record, poc), alice: alice}
    end

    defp reload(case_record, actor) do
      Cases.get_case!(case_record.id,
        actor: actor,
        load: [:weaknesses, :credits, affected_packages: [:channels]]
      )
    end

    test "a scalar replaces the case's value", %{poc: poc, case: case_record, link: link} do
      Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)

      assert {:ok, _link} = Cases.pull_github_advisory(link, [:title], actor: poc)
      assert reload(case_record, poc).title == "Header injection in acme_lib"
    end

    test "the scalars arrive together", %{poc: poc, case: case_record, link: link} do
      GitHubApi.stub_advisory(put_in(hex_advisory(), ["cvss_severities", "cvss_v4", "vector_string"], @vector))

      link = Cases.refresh_github_advisory_link!(link, actor: poc)
      Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)

      assert {:ok, _link} = Cases.pull_github_advisory(link, [:title, :cvss_v4], actor: poc)

      reloaded = reload(case_record, poc)
      assert reloaded.title == "Header injection in acme_lib"
      assert reloaded.cvss_v4.vector == @vector
    end

    test "sets gain what the case lacks and lose nothing", %{
      poc: poc,
      case: case_record,
      link: link,
      alice: alice
    } do
      Fixtures.seed_weakness(79, "Cross-site Scripting")
      Cases.add_case_weakness!(%{case_id: case_record.id, cwe_id: 79}, actor: poc)

      Cases.add_case_credit!(%{case_id: case_record.id, name: "Bob", credit_type: :reporter},
        actor: poc
      )

      assert {:ok, _link} = Cases.pull_github_advisory(link, [:weaknesses, :credits], actor: poc)

      reloaded = reload(case_record, poc)

      assert reloaded.weaknesses |> Enum.map(&{&1.cwe_id, &1.position}) |> Enum.sort() ==
               [{79, 0}, {113, 1}]

      assert Enum.map(reloaded.credits, &{&1.name, &1.credit_type, &1.user_id, &1.position}) == [
               {"Bob", :reporter, nil, 0},
               {"alice name", :finder, alice.id, 1}
             ]

      assert {:ok, _link} = Cases.pull_github_advisory(link, [:weaknesses, :credits], actor: poc)
      assert length(reload(case_record, poc).credits) == 2
    end

    test "a credited person without an account here is named from their GitHub profile", %{
      poc: poc,
      case: case_record,
      link: link
    } do
      advisory =
        Map.put(hex_advisory(), "credits_detailed", [
          %{"state" => "accepted", "type" => "finder", "user" => %{"login" => "carol"}}
        ])

      GitHubApi.stub_advisory(advisory, %{"carol" => "Carol Example"})
      link = Cases.refresh_github_advisory_link!(link, actor: poc)

      assert {:ok, _link} = Cases.pull_github_advisory(link, [:credits], actor: poc)

      assert [%{name: "Carol Example", credit_type: :finder, user_id: nil}] =
               reload(case_record, poc).credits
    end

    test "affected packages arrive with their channels and no boundaries, once", %{
      poc: poc,
      case: case_record,
      link: link
    } do
      assert {:ok, _link} = Cases.pull_github_advisory(link, [:affected], actor: poc)

      assert [%{vendor: "acme", product: "acme_lib", channels: channels}] =
               reload(case_record, poc).affected_packages

      assert channels |> Enum.map(&{&1.purl_type, &1.name}) |> Enum.sort() ==
               [{"github", "acme_lib"}, {"hex", "acme_lib"}]

      assert {:ok, _link} = Cases.pull_github_advisory(link, [:affected], actor: poc)
      assert length(reload(case_record, poc).affected_packages) == 1
      assert Cases.list_version_events!(actor: poc) == []
    end

    test "a frozen case takes nothing", %{poc: poc, case: case_record, link: link} do
      approve!(case_record, poc)

      assert {:error, %Forbidden{}} = Cases.pull_github_advisory(link, [:title], actor: poc)
      assert reload(case_record, poc).title == "Header injection in acme_lib"
    end

    test "an assigned supporter pulls", %{poc: poc, case: case_record, link: link} do
      supporter = Fixtures.register_user("pull_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)

      assert {:ok, _link} = Cases.pull_github_advisory(link, [:title], actor: supporter)
      assert reload(case_record, poc).title == "Header injection in acme_lib"
    end

    test "nobody else pulls", %{poc: poc, case: case_record, link: link} do
      collaborator = Fixtures.register_user("pull_collaborator")
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: collaborator.id}, actor: poc)
      stranger = Fixtures.register_user("pull_stranger", :supporter)

      assert {:error, %Forbidden{}} = Cases.pull_github_advisory(link, [:title], actor: nil)

      assert {:error, %Forbidden{}} =
               Cases.pull_github_advisory(link, [:title], actor: collaborator)

      assert {:error, %Forbidden{}} = Cases.pull_github_advisory(link, [:title], actor: stranger)
    end

    test "an unknown field or none is refused", %{poc: poc, link: link} do
      assert {:error, %Invalid{errors: [%{field: :fields}]}} =
               Cases.pull_github_advisory(link, [:description_md], actor: poc)

      assert {:error, %Invalid{errors: [%{field: :fields}]}} =
               Cases.pull_github_advisory(link, [], actor: poc)
    end
  end

  describe "push" do
    setup %{poc: poc, case: case_record} do
      Fixtures.seed_weakness(113, "Improper Neutralization of CRLF Sequences in HTTP Headers")
      Cases.add_case_weakness!(%{case_id: case_record.id, cwe_id: 113}, actor: poc)
      Cases.edit_case!(case_record, %{title: "Header injection in acme_lib, revised"}, actor: poc)

      %{link: link!(case_record, poc)}
    end

    defp stub_update(answer) do
      test_pid = self()

      GitHubApi.stub(fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)

        send(
          test_pid,
          {:github, conn.method, conn.request_path, Plug.Conn.get_req_header(conn, "authorization"), JSON.decode!(body)}
        )

        Req.Test.json(conn, answer)
      end)
    end

    defp stub_refusal(status, body) do
      GitHubApi.stub(fn conn -> conn |> Plug.Conn.put_status(status) |> Req.Test.json(body) end)
    end

    test "writes the chosen fields as the caller and stores what GitHub answered", %{
      poc: poc,
      link: link
    } do
      stub_update(Map.put(hex_advisory(), "summary", "Header injection in acme_lib, revised"))

      assert {:ok, pushed} = Cases.push_github_advisory(link, [:title, :weaknesses], actor: poc)

      assert_received {:github, "PATCH", "/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw",
                       ["Bearer gho_token"], body}

      assert body == %{
               "summary" => "Header injection in acme_lib, revised",
               "cwe_ids" => ["CWE-113"]
             }

      assert pushed.title == "Header injection in acme_lib, revised"
      assert pushed.__metadata__.skipped_credits == []
    end

    test "credits keep the advisory's, add those with a GitHub account, and name the rest", %{
      poc: poc,
      case: case_record,
      link: link
    } do
      bob = Fixtures.register_user("bob")

      Cases.add_case_credit!(
        %{case_id: case_record.id, name: "Bob", credit_type: :analyst, user_id: bob.id},
        actor: poc
      )

      Cases.add_case_credit!(
        %{case_id: case_record.id, name: "Nobody Here", credit_type: :reporter},
        actor: poc
      )

      stub_update(hex_advisory())

      assert {:ok, pushed} = Cases.push_github_advisory(link, [:credits], actor: poc)

      assert_received {:github, "PATCH", _path, _auth, %{"credits" => credits}}

      assert credits == [
               %{"login" => "alice", "type" => "finder"},
               %{"login" => "bob", "type" => "analyst"}
             ]

      assert pushed.__metadata__.skipped_credits == ["Nobody Here"]
    end

    test "affected packages travel as the derived ranges of each channel", %{
      poc: poc,
      case: case_record,
      link: link
    } do
      package = Fixtures.add_affected_package(poc, case_record)

      hex =
        Cases.add_package_channel!(
          %{
            case_id: case_record.id,
            affected_package_id: package.id,
            purl_type: "hex",
            name: "acme_lib"
          },
          actor: poc
        )

      Ash.update!(
        package,
        %{
          derivation_cache: %{
            "channels" => %{
              hex.id => %{
                "github_ranges" => [
                  %{"vulnerable_version_range" => "< 1.2.3", "patched_versions" => ["1.2.3"]}
                ]
              }
            }
          }
        },
        action: :store_derivation,
        authorize?: false
      )

      stub_update(hex_advisory())

      assert {:ok, _pushed} = Cases.push_github_advisory(link, [:affected], actor: poc)

      assert_received {:github, "PATCH", _path, _auth, %{"vulnerabilities" => vulnerabilities}}

      assert vulnerabilities == [
               %{
                 "package" => %{"ecosystem" => "erlang", "name" => "acme_lib"},
                 "vulnerable_version_range" => "< 1.2.3",
                 "patched_versions" => "1.2.3"
               }
             ]
    end

    test "pushing affected packages keeps the advisory's entries the case does not derive", %{
      poc: poc,
      case: case_record,
      link: link
    } do
      not_derived = %{
        "package" => %{"ecosystem" => "erlang", "name" => "acme_extra"},
        "vulnerable_version_range" => "< 0.3.0",
        "patched_versions" => "0.3.0",
        "vulnerable_functions" => []
      }

      no_channel = %{
        "package" => %{"ecosystem" => "other", "name" => "acme_widget"},
        "vulnerable_version_range" => "< 2.0.0",
        "patched_versions" => "2.0.0",
        "vulnerable_functions" => []
      }

      advisory =
        Map.update!(hex_advisory(), "vulnerabilities", &(&1 ++ [not_derived, no_channel]))

      GitHubApi.stub_advisory(advisory)
      link = Cases.refresh_github_advisory_link!(link, actor: poc)

      package = Fixtures.add_affected_package(poc, case_record)

      [hex, extra] =
        for name <- ["acme_lib", "acme_extra"] do
          Cases.add_package_channel!(
            %{
              case_id: case_record.id,
              affected_package_id: package.id,
              purl_type: "hex",
              name: name
            },
            actor: poc
          )
        end

      Ash.update!(
        package,
        %{
          derivation_cache: %{
            "channels" => %{
              hex.id => %{
                "github_ranges" => [
                  %{"vulnerable_version_range" => "< 1.2.3", "patched_versions" => ["1.2.3"]}
                ]
              },
              extra.id => %{"github_ranges" => []}
            }
          }
        },
        action: :store_derivation,
        authorize?: false
      )

      stub_update(advisory)

      assert {:ok, _pushed} = Cases.push_github_advisory(link, [:affected], actor: poc)

      assert_received {:github, "PATCH", _path, _auth, %{"vulnerabilities" => vulnerabilities}}

      assert vulnerabilities == [
               %{
                 "package" => %{"ecosystem" => "erlang", "name" => "acme_lib"},
                 "vulnerable_version_range" => "< 1.2.3",
                 "patched_versions" => "1.2.3"
               },
               not_derived,
               no_channel
             ]
    end

    test "stays open on an approved case", %{poc: poc, case: case_record, link: link} do
      approve!(Cases.get_case!(case_record.id, actor: poc), poc)
      stub_update(hex_advisory())

      assert {:ok, _pushed} = Cases.push_github_advisory(link, [:title], actor: poc)
      assert_received {:github, "PATCH", _path, _auth, %{"summary" => _title}}
    end

    test "a refusal from GitHub changes nothing here", %{poc: poc, link: link} do
      stub_refusal(403, %{"message" => "Resource not accessible by integration"})

      assert {:error, %Invalid{errors: [%{field: :fields, message: message}]}} =
               Cases.push_github_advisory(link, [:title], actor: poc)

      assert message == "was refused by GitHub: Resource not accessible by integration"
      assert Ash.reload!(link, authorize?: false).title == "Header injection in acme_lib"
    end

    test "an advisory GitHub no longer shows the caller is refused", %{poc: poc, link: link} do
      stub_refusal(404, %{"message" => "Not Found"})

      assert {:error, %Invalid{errors: [%{field: :fields, message: message}]}} =
               Cases.push_github_advisory(link, [:title], actor: poc)

      assert message == "was refused: GitHub shows you no such advisory"
    end

    test "needs the caller's GitHub account, before GitHub is asked", %{link: link} do
      stub_github_unreachable()
      hex_poc = Fixtures.sign_in_with_hex("push_hex", "push_hex")
      hex_poc = Ash.update!(hex_poc, %{role: :poc}, action: :set_role, authorize?: false)

      assert {:error, %Invalid{errors: [%{field: :fields, message: message}]}} =
               Cases.push_github_advisory(link, [:title], actor: hex_poc)

      assert message == "needs your GitHub account linked"
    end

    test "a global database entry is not pushed", %{poc: poc} do
      other = Fixtures.open_case(poc, %{title: "Global case"})

      hex_advisory()
      |> Map.put("ghsa_id", "GHSA-pwvh-c689-f8q5")
      |> Map.put("html_url", "https://github.com/advisories/GHSA-pwvh-c689-f8q5")
      |> GitHubApi.stub_advisory()

      link = link!(other, poc, "GHSA-pwvh-c689-f8q5")
      stub_github_unreachable()

      assert {:error, %Invalid{errors: [%{field: :fields, message: message}]}} =
               Cases.push_github_advisory(link, [:title], actor: poc)

      assert message == "cannot be pushed: the advisory is a global database entry"
    end

    test "an assigned supporter pushes", %{poc: poc, case: case_record, link: link} do
      supporter = Fixtures.register_user("push_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      stub_update(hex_advisory())

      assert {:ok, _pushed} = Cases.push_github_advisory(link, [:title], actor: supporter)
      assert_received {:github, "PATCH", _path, ["Bearer gho_token"], _body}
    end

    test "nobody else pushes, and is refused before GitHub is asked", %{
      poc: poc,
      case: case_record,
      link: link
    } do
      collaborator = Fixtures.register_user("push_collaborator")
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: collaborator.id}, actor: poc)
      nobody = Fixtures.register_user("push_nobody")
      stranger = Fixtures.register_user("push_stranger", :supporter)
      stub_github_unreachable()

      for actor <- [nil, collaborator, nobody, stranger] do
        assert {:error, %Forbidden{}} = Cases.push_github_advisory(link, [:title], actor: actor)
      end
    end
  end

  test "the diff sets the case against the stored advisory", %{poc: poc, case: case_record} do
    link = link!(case_record, poc)

    rows = Ash.load!(link, :diff, actor: poc).diff

    assert %{field: :title, status: :same} = Enum.find(rows, &(&1.field == :title))

    assert %{field: :affected, package: "erlang/acme_lib", status: :theirs_only} =
             Enum.find(rows, &(&1.field == :affected))
  end

  test "recording an advisory is reserved to the case's own actions", %{
    poc: poc,
    case: case_record
  } do
    assert {:error, %Forbidden{}} =
             Cases.record_github_advisory_link(
               %{case_id: case_record.id, advisory: hex_advisory()},
               actor: poc
             )
  end

  describe "who may" do
    setup %{poc: poc, case: case_record} do
      supporter = Fixtures.register_user("link_supporter", :supporter)
      collaborator = Fixtures.register_user("link_collaborator")

      for user <- [supporter, collaborator] do
        Cases.assign_case_user!(%{case_id: case_record.id, user_id: user.id}, actor: poc)
      end

      %{supporter: supporter, collaborator: collaborator}
    end

    test "nobody signed in is refused before GitHub is asked", %{poc: poc, case: case_record} do
      stub_github_unreachable()

      assert {:error, %Forbidden{}} = link(case_record, nil)
      assert {:error, %Forbidden{}} = Ash.read(GitHubAdvisoryLink, actor: nil)

      GitHubApi.stub_advisory(hex_advisory())
      link = link!(case_record, poc)
      stub_github_unreachable()

      assert {:error, %Forbidden{}} = Cases.refresh_github_advisory_link(link, actor: nil)
      assert {:error, %Forbidden{}} = Cases.unlink_github_advisory(link, actor: nil)
    end

    test "a signed-in person without a role or an assignment is refused before GitHub is asked",
         %{poc: poc, case: case_record} do
      stub_github_unreachable()
      stranger = Fixtures.register_user("link_nobody")

      assert {:error, %Forbidden{}} = link(case_record, stranger)
      assert Ash.read!(GitHubAdvisoryLink, actor: stranger) == []

      GitHubApi.stub_advisory(hex_advisory())
      link = link!(case_record, poc)
      stub_github_unreachable()

      assert {:error, %Forbidden{}} = Cases.refresh_github_advisory_link(link, actor: stranger)
      assert {:error, %Forbidden{}} = Cases.unlink_github_advisory(link, actor: stranger)
    end

    test "a link naming no case is refused before GitHub is asked", %{poc: poc} do
      stub_github_unreachable()

      for actor <- [nil, poc] do
        assert {:error, %Invalid{errors: [%Ash.Error.Changes.Required{field: :case_id}]}} =
                 Cases.link_github_advisory(%{advisory_url: @hex_url}, actor: actor)
      end
    end

    test "an assigned supporter links, refreshes and unlinks", %{
      case: case_record,
      supporter: supporter
    } do
      link = link!(case_record, supporter)
      assert %GitHubAdvisoryLink{} = Cases.refresh_github_advisory_link!(link, actor: supporter)
      assert :ok = Cases.unlink_github_advisory(link, actor: supporter)
    end

    test "an assigned collaborator without a role reads and refreshes, and nothing more", %{
      poc: poc,
      case: case_record,
      collaborator: collaborator
    } do
      stub_github_unreachable()
      assert {:error, %Forbidden{}} = link(case_record, collaborator)

      GitHubApi.stub_advisory(hex_advisory())
      link = link!(case_record, poc)

      assert %GitHubAdvisoryLink{} =
               Cases.refresh_github_advisory_link!(link, actor: collaborator)

      assert {:error, %Forbidden{}} = Cases.unlink_github_advisory(link, actor: collaborator)

      assert Cases.get_case!(case_record.id, actor: collaborator, load: [:github_advisory_link]).github_advisory_link.id ==
               link.id
    end

    test "a supporter off the case sees and does nothing", %{poc: poc, case: case_record} do
      stub_github_unreachable()
      stranger = Fixtures.register_user("link_stranger", :supporter)

      assert {:error, %Forbidden{}} = link(case_record, stranger)

      GitHubApi.stub_advisory(hex_advisory())
      link = link!(case_record, poc)

      assert {:error, %Forbidden{}} = Cases.refresh_github_advisory_link(link, actor: stranger)
      assert {:error, %Forbidden{}} = Cases.unlink_github_advisory(link, actor: stranger)
      assert Ash.read!(GitHubAdvisoryLink, actor: stranger) == []
    end

    test "an approved case keeps its link as it is, and still refreshes", %{
      poc: poc,
      case: case_record,
      supporter: supporter
    } do
      link = link!(case_record, poc)
      approve!(case_record, poc)

      assert {:error, %Forbidden{}} = Cases.unlink_github_advisory(link, actor: poc)
      assert {:error, %Forbidden{}} = Cases.unlink_github_advisory(link, actor: supporter)
      assert %GitHubAdvisoryLink{} = Cases.refresh_github_advisory_link!(link, actor: poc)
      assert %GitHubAdvisoryLink{} = Cases.refresh_github_advisory_link!(link, actor: supporter)
    end

    test "an approved case takes no link", %{poc: poc} do
      other = Fixtures.open_case(poc, %{title: "Approved case"})
      approve!(other, poc)
      stub_github_unreachable()

      assert {:error, %Forbidden{}} = link(other, poc)
    end
  end
end
