# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.AttackPatternToolTest do
  @moduledoc """
  The CAPEC tools project an attack pattern down to what each call is for:
  collections identify, `get_attack_pattern` carries the prose, and the
  relations tool carries the links. Cross-references stay identified rather than
  expanded, since a nested CWE arriving whole outweighs the record requested.
  """

  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias Varsel.CAPEC.AttackPattern
  alias Varsel.CAPEC.AttackPatternRelationship
  alias Varsel.CAPEC.AttackPatternWeakness
  alias Varsel.CWE.Weakness

  @prose_fields ~w(extended_description prerequisites mitigations consequences)

  setup do
    poc = register_user("poc", :poc)

    seed_attack_pattern_with_prose(63, "Cross-Site Scripting")
    seed_attack_pattern_with_prose(66, "SQL Injection")

    Ash.Seed.seed!(Weakness, %{
      cwe_id: 79,
      name: "Improper Neutralization of Input",
      abstraction: :base,
      status: :stable,
      description: "CWE description",
      potential_mitigations: String.duplicate("cwe mitigation ", 20),
      common_consequences: String.duplicate("cwe consequence ", 20)
    })

    Ash.Seed.seed!(AttackPatternWeakness, %{capec_id: 63, cwe_id: 79})

    Ash.Seed.seed!(AttackPatternRelationship, %{
      source_capec_id: 63,
      target_capec_id: 66,
      nature: :child_of
    })

    {:ok, actor: poc}
  end

  defp seed_attack_pattern_with_prose(capec_id, name) do
    Ash.Seed.seed!(AttackPattern, %{
      capec_id: capec_id,
      name: name,
      abstraction: :standard,
      status: :stable,
      likelihood_of_attack: :high,
      typical_severity: :high,
      description: "#{name} description",
      extended_description: String.duplicate("extended prose ", 30),
      prerequisites: String.duplicate("prerequisite ", 30),
      mitigations: String.duplicate("mitigation guidance ", 40),
      consequences: String.duplicate("consequence note ", 30)
    })
  end

  defp run(tool_name, arguments, actor) do
    tool = Enum.find(AshAi.exposed_tools(otp_app: :varsel), &(&1.name == tool_name))
    assert tool, "no tool named #{tool_name} is exposed"

    {:ok, json, _raw} = AshAi.Tools.execute(tool, arguments, %{actor: actor})
    Jason.decode!(json)
  end

  describe "collections" do
    test "list_attack_patterns carries only what identifies a pattern", %{actor: actor} do
      rows = run(:list_attack_patterns, %{}, actor)

      assert length(rows) == 2

      for row <- rows do
        assert Enum.sort(Map.keys(row)) == ~w(capec_id description name)
      end
    end

    test "search_attack_patterns carries the same projection", %{actor: actor} do
      rows = run(:search_attack_patterns, %{"input" => %{"query" => "SQL"}}, actor)

      assert [%{"capec_id" => 66}] = rows
      assert Enum.sort(Map.keys(hd(rows))) == ~w(capec_id description name)
    end

    test "a collection never carries the prose fields", %{actor: actor} do
      json = :list_attack_patterns |> run(%{}, actor) |> Jason.encode!()

      for field <- @prose_fields, do: refute(json =~ field)
    end
  end

  describe "get_attack_pattern" do
    test "carries every field of the record", %{actor: actor} do
      [row] = run(:get_attack_pattern, %{"input" => %{"capec_id" => 63}}, actor)

      assert Enum.sort(Map.keys(row)) ==
               ~w(abstraction capec_id consequences description extended_description
                  likelihood_of_attack mitigations name prerequisites status
                  typical_severity)

      assert row["capec_id"] == 63
      assert row["mitigations"] =~ "mitigation guidance"
    end

    test "loads no relationships", %{actor: actor} do
      [row] = run(:get_attack_pattern, %{"input" => %{"capec_id" => 63}}, actor)

      refute Map.has_key?(row, "weaknesses")
      refute Map.has_key?(row, "related_attack_pattern_relationships")
    end
  end

  describe "get_attack_pattern_relations" do
    test "related weaknesses are identified, not expanded", %{actor: actor} do
      [row] = run(:get_attack_pattern_relations, %{"input" => %{"capec_id" => 63}}, actor)

      assert Enum.sort(Map.keys(row)) ==
               ~w(capec_id name related_attack_pattern_relationships weaknesses)

      assert [weakness] = row["weaknesses"]
      assert Enum.sort(Map.keys(weakness)) == ~w(cwe_id name)
      assert weakness["cwe_id"] == 79
    end

    test "related attack patterns are identified, not expanded", %{actor: actor} do
      [row] = run(:get_attack_pattern_relations, %{"input" => %{"capec_id" => 63}}, actor)

      assert [relationship] = row["related_attack_pattern_relationships"]
      assert relationship["nature"] == "child_of"

      assert Enum.sort(Map.keys(relationship["target"])) == ~w(capec_id name)
      assert relationship["target"]["capec_id"] == 66
    end

    test "no nested record drags its own prose along", %{actor: actor} do
      json =
        :get_attack_pattern_relations
        |> run(%{"input" => %{"capec_id" => 63}}, actor)
        |> Jason.encode!()

      for field <- @prose_fields ++ ~w(potential_mitigations common_consequences) do
        refute json =~ field, "get_attack_pattern_relations leaked #{field}"
      end
    end
  end

  test "a listed pattern is a fraction of the detail payload", %{actor: actor} do
    [summary | _] = run(:list_attack_patterns, %{}, actor)
    [detail] = run(:get_attack_pattern, %{"input" => %{"capec_id" => 63}}, actor)

    assert byte_size(Jason.encode!(summary)) * 10 < byte_size(Jason.encode!(detail))
  end
end
