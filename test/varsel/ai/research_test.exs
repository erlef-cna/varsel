# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.AI.ResearchTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.CVE
  alias Varsel.Fixtures
  alias Varsel.Test.StubAIBackend

  setup do
    poc = Fixtures.register_user("research_poc", :poc)
    reporter = Fixtures.register_user("research_reporter")

    report =
      CVE.submit_vulnerability_report!(
        %{
          report_json: %{
            "package" => "acme_lib",
            "details" => "Auth bypass, fixed in 1.2.4",
            "advisory" => "https://github.com/acme/acme_lib/security/advisories/GHSA-x"
          },
          summary: "Auth bypass in acme_lib",
          confirms_criteria: true,
          confirms_in_scope: true
        },
        actor: reporter
      )

    report = CVE.accept_vulnerability_report!(report, %{}, actor: poc)
    case_record = Ash.load!(report, :case, authorize?: false).case

    %{poc: poc, case: case_record, report: report}
  end

  defp text_of(%ReqLLM.Message{content: content}) when is_binary(content), do: content

  defp text_of(%ReqLLM.Message{content: parts}) do
    parts |> Enum.map(& &1.text) |> Enum.reject(&is_nil/1) |> Enum.join()
  end

  test "files proposals through tools and posts the research notes", %{
    poc: poc,
    case: case_record
  } do
    Application.put_env(:varsel, :hex_stub_packages, %{"acme_lib" => ["1.2.3", "1.2.4"]})
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)

    notes = "## AI research notes\n\nProposed acme_lib as affected package (hex.pm, advisory)."

    StubAIBackend.stub_script([
      {:tool_calls, [{"hex_package_info", %{"input" => %{"name" => "acme_lib"}}}]},
      {:tool_calls,
       [
         {"create_case_proposal",
          %{
            "input" => %{
              "case_id" => case_record.id,
              "target" => "affected_package",
              "operation" => "insert",
              "proposed_value" => %{
                "value" => %{
                  "vendor" => "acme",
                  "product" => "acme_lib",
                  "repo_url" => "https://github.com/acme/acme_lib"
                }
              },
              "reasoning" => "hex.pm lists acme_lib; report names it as affected."
            }
          }}
       ]},
      {:tool_calls, [{"create_case_comment", %{"input" => %{"case_id" => case_record.id, "body" => notes}}}]},
      {:text, notes},
      {:result, notes}
    ])

    assert {:ok, ^notes} = Cases.research_case(case_record.id, actor: poc)

    # The proposal was filed as the invoking user, ready for review.
    assert [proposal] = Cases.list_open_case_proposals!(case_record.id, actor: poc)
    assert proposal.target == :affected_package
    assert proposal.operation == :insert
    assert proposal.proposed_value["value"]["product"] == "acme_lib"
    assert proposal.author_id == poc.id

    assert [comment] = Cases.list_case_comments!(case_record.id, actor: poc)
    assert comment.body =~ "AI research notes"

    # The hex lookup ran against hex.pm (stubbed) and fed the loop.
    requests = StubAIBackend.requests()
    assert [{:stream_text, first} | _rest] = requests

    [system, user] = first
    assert text_of(system) =~ "Allowed targets and their fields"
    assert text_of(system) =~ "affected_package: vendor, product, repo_url"
    assert text_of(user) =~ case_record.id
    assert text_of(user) =~ "Auth bypass in acme_lib"

    {:stream_text, second} = Enum.at(requests, 1)
    tool_result = List.last(second)
    assert tool_result.role == :tool
    assert text_of(tool_result) =~ "1.2.4"
  end

  test "tool errors feed back into the loop instead of aborting", %{
    poc: poc,
    case: case_record
  } do
    notes = "## AI research notes\n\nCould not verify anything."

    StubAIBackend.stub_script([
      # :state is not a proposable field — the proposal is rejected.
      {:tool_calls,
       [
         {"create_case_proposal",
          %{
            "input" => %{
              "case_id" => case_record.id,
              "target" => "case",
              "operation" => "set",
              "field_name" => "state",
              "proposed_value" => %{"value" => "published"},
              "reasoning" => "nope"
            }
          }}
       ]},
      {:text, notes},
      {:result, notes}
    ])

    assert {:ok, ^notes} = Cases.research_case(case_record.id, actor: poc)
    assert [] = Cases.list_open_case_proposals!(case_record.id, actor: poc)

    {:stream_text, second} = Enum.at(StubAIBackend.requests(), 1)
    tool_result = List.last(second)
    assert tool_result.role == :tool
    assert text_of(tool_result) =~ "field_name"
  end

  test "supporters not assigned to the case cannot research it", %{case: case_record} do
    outsider = Fixtures.register_user("research_outsider", :supporter)

    assert {:error, %Ash.Error.Forbidden{}} =
             Cases.research_case(case_record.id, actor: outsider)
  end
end
