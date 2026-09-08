# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLinkTest do
  @moduledoc """
  Linking a case to a GitHub advisory: what the link stores, the reference it
  adds, how it is refreshed and removed, and who may do each.
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
