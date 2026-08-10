# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseToolTest do
  @moduledoc """
  The case tools return what each call is for. A proposal listing is the
  reusable payload rather than every author's reasoning, and a validation or
  preview is the verdict rather than the whole case echoed back to deliver it.
  """

  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias Varsel.Cases

  @case_body ~w(description_md workarounds_md configurations_md solutions_md internal_notes)

  setup do
    poc = register_user("poc", :poc)

    case_record =
      open_case(poc, %{
        title: "A case",
        description_md: String.duplicate("description prose ", 30),
        workarounds_md: String.duplicate("workaround prose ", 30),
        configurations_md: String.duplicate("configuration prose ", 30),
        solutions_md: String.duplicate("solution prose ", 30),
        internal_notes: String.duplicate("internal note ", 30)
      })

    Cases.propose_title!(
      %{
        case_id: case_record.id,
        value: "Better title",
        reasoning: String.duplicate("a long paragraph of reasoning ", 40)
      },
      actor: poc
    )

    {:ok, actor: poc, case_record: case_record}
  end

  defp run(tool_name, arguments, actor) do
    tool =
      Enum.find(AshAi.exposed_tools(otp_app: :varsel, actor: actor), &(&1.name == tool_name))

    assert tool, "no tool named #{tool_name} is exposed"

    {:ok, json, _raw} = AshAi.Tools.execute(tool, arguments, %{actor: actor})
    Jason.decode!(json)
  end

  describe "proposal listings" do
    test "list_case_proposals carries the reusable payload, not the reasoning", %{
      actor: actor,
      case_record: case_record
    } do
      [row] = run(:list_case_proposals, %{"input" => %{"case_id" => case_record.id}}, actor)

      assert Enum.sort(Map.keys(row)) ==
               ~w(field_name id operation proposed_value state target)

      assert row["field_name"] == "title"
      assert row["proposed_value"] == %{"value" => "Better title"}
    end

    test "list_open_case_proposals carries the same projection", %{
      actor: actor,
      case_record: case_record
    } do
      [row] = run(:list_open_case_proposals, %{"input" => %{"case_id" => case_record.id}}, actor)

      refute Map.has_key?(row, "reasoning")
      assert row["state"] == "open"
    end

    test "a listing never carries reasoning", %{actor: actor, case_record: case_record} do
      json =
        :list_case_proposals
        |> run(%{"input" => %{"case_id" => case_record.id}}, actor)
        |> Jason.encode!()

      refute json =~ "reasoning"
      refute json =~ "a long paragraph of reasoning"
    end
  end

  describe "get_case_proposal" do
    test "carries the full reasoning for a single proposal", %{
      actor: actor,
      case_record: case_record
    } do
      [listed] = run(:list_case_proposals, %{"input" => %{"case_id" => case_record.id}}, actor)

      [row] = run(:get_case_proposal, %{"input" => %{"id" => listed["id"]}}, actor)

      assert row["reasoning"] =~ "a long paragraph of reasoning"
      assert row["id"] == listed["id"]
    end
  end

  describe "validate_case and render_case_preview" do
    test "validate_case returns the verdict, not the case body", %{
      actor: actor,
      case_record: case_record
    } do
      [row] = run(:validate_case, %{"filter" => %{"id" => %{"eq" => case_record.id}}}, actor)

      assert Enum.sort(Map.keys(row)) == ~w(id validation)
      assert is_map(row["validation"])
      assert Map.has_key?(row["validation"], "errors")
    end

    test "render_case_preview returns the preview, not the case body", %{
      actor: actor,
      case_record: case_record
    } do
      [row] =
        run(:render_case_preview, %{"filter" => %{"id" => %{"eq" => case_record.id}}}, actor)

      assert Enum.sort(Map.keys(row)) == ~w(id preview)
    end

    test "neither echoes the markdown fields or the internal notes", %{
      actor: actor,
      case_record: case_record
    } do
      for tool <- [:validate_case, :render_case_preview] do
        row = run(tool, %{"filter" => %{"id" => %{"eq" => case_record.id}}}, actor)

        for field <- @case_body do
          refute Map.has_key?(hd(row), field), "#{tool} echoed #{field}"
        end
      end
    end

    test "internal notes never reach a validation response", %{
      actor: actor,
      case_record: case_record
    } do
      json =
        :validate_case
        |> run(%{"filter" => %{"id" => %{"eq" => case_record.id}}}, actor)
        |> Jason.encode!()

      refute json =~ "internal note"
    end
  end

  test "get_case still carries the case body", %{actor: actor} do
    [row] = run(:get_case, %{}, actor)

    assert row["description_md"] =~ "description prose"
  end
end
