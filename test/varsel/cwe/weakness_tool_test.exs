# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.WeaknessToolTest do
  @moduledoc """
  The CWE tools project a weakness down to what each call is for: collections
  identify, `get_weakness` carries the prose, and the relationship tools carry
  the links. Nothing else may ride along, since the mitigations and consequences
  of a single weakness outweigh every other field combined.
  """

  use Varsel.DataCase, async: false

  import Varsel.Fixtures

  alias Varsel.CAPEC.AttackPattern
  alias Varsel.CAPEC.AttackPatternWeakness
  alias Varsel.CWE.Weakness
  alias Varsel.CWE.WeaknessRelationship

  @bulk_fields ~w(extended_description potential_mitigations common_consequences)

  setup do
    poc = register_user("poc", :poc)

    seed_weakness_with_prose(79, "Cross-site Scripting")
    seed_weakness_with_prose(74, "Injection")

    Ash.Seed.seed!(AttackPattern, %{
      capec_id: 63,
      name: "Cross-Site Scripting",
      abstraction: :standard,
      status: :stable,
      description: "CAPEC description",
      mitigations: String.duplicate("capec mitigation ", 20),
      prerequisites: String.duplicate("capec prerequisite ", 20)
    })

    Ash.Seed.seed!(AttackPatternWeakness, %{capec_id: 63, cwe_id: 79})

    seed_view(1000, "Research Concepts")

    Ash.Seed.seed!(WeaknessRelationship, %{
      source_cwe_id: 79,
      target_cwe_id: 74,
      nature: :child_of,
      view_id: 1000
    })

    {:ok, actor: poc}
  end

  defp seed_weakness_with_prose(cwe_id, name) do
    Ash.Seed.seed!(Weakness, %{
      cwe_id: cwe_id,
      name: name,
      abstraction: :base,
      status: :stable,
      description: "#{name} description",
      extended_description: String.duplicate("extended prose ", 30),
      potential_mitigations: String.duplicate("mitigation guidance ", 40),
      common_consequences: String.duplicate("consequence note ", 30)
    })
  end

  defp run(tool_name, arguments, actor) do
    tool = Enum.find(AshAi.exposed_tools(otp_app: :varsel), &(&1.name == tool_name))
    assert tool, "no tool named #{tool_name} is exposed"

    {:ok, json, _raw} = AshAi.Tools.execute(tool, arguments, %{actor: actor})
    Jason.decode!(json)
  end

  describe "collections" do
    test "list_weaknesses carries only what identifies a weakness", %{actor: actor} do
      rows = run(:list_weaknesses, %{}, actor)

      assert length(rows) == 2

      for row <- rows do
        assert Enum.sort(Map.keys(row)) == ~w(cwe_id description name)
      end
    end

    test "search_weaknesses carries the same projection", %{actor: actor} do
      rows = run(:search_weaknesses, %{"input" => %{"query" => "Injection"}}, actor)

      assert [%{"cwe_id" => 74}] = rows
      assert Enum.sort(Map.keys(hd(rows))) == ~w(cwe_id description name)
    end

    test "a collection never carries the prose fields", %{actor: actor} do
      json = :list_weaknesses |> run(%{}, actor) |> Jason.encode!()

      for field <- @bulk_fields, do: refute(json =~ field)
    end
  end

  describe "get_weakness" do
    test "carries the prose a caller asked for it by ID to read", %{actor: actor} do
      row = run(:get_weakness, %{"cwe_id" => 79}, actor)

      assert Enum.sort(Map.keys(row)) ==
               ~w(common_consequences cwe_id description extended_description name
                  potential_mitigations)

      assert row["cwe_id"] == 79
      assert row["potential_mitigations"] =~ "mitigation guidance"
    end

    test "loads no relationships", %{actor: actor} do
      row = run(:get_weakness, %{"cwe_id" => 79}, actor)

      refute Map.has_key?(row, "related_attack_patterns")
      refute Map.has_key?(row, "related_weakness_relationships")
    end
  end

  describe "relationship tools" do
    test "related attack patterns are identified, not expanded", %{actor: actor} do
      row = run(:get_weakness_related_attack_patterns, %{"cwe_id" => 79}, actor)

      assert Enum.sort(Map.keys(row)) == ~w(cwe_id name related_attack_patterns)
      assert [capec] = row["related_attack_patterns"]
      assert Enum.sort(Map.keys(capec)) == ~w(capec_id description name)
      assert capec["capec_id"] == 63

      # The defect this projection exists to prevent: a nested CAPEC arriving
      # whole, several times the size of the record actually requested.
      refute Map.has_key?(capec, "mitigations")
      refute Map.has_key?(capec, "prerequisites")
    end

    test "related weaknesses are identified, not expanded", %{actor: actor} do
      row = run(:get_weakness_related_weaknesses, %{"cwe_id" => 79}, actor)

      assert Enum.sort(Map.keys(row)) == ~w(cwe_id name related_weakness_relationships)
      assert [relationship] = row["related_weakness_relationships"]
      assert relationship["nature"] == "child_of"

      for side <- ~w(source target), record = relationship[side], is_map(record) do
        assert Enum.sort(Map.keys(record)) == ~w(cwe_id name)
      end
    end

    test "neither relationship tool leaks the prose fields", %{actor: actor} do
      for tool <- [:get_weakness_related_weaknesses, :get_weakness_related_attack_patterns] do
        json = tool |> run(%{"cwe_id" => 79}, actor) |> Jason.encode!()

        for field <- @bulk_fields, do: refute(json =~ field, "#{tool} leaked #{field}")
      end
    end
  end

  test "a listed weakness is a fraction of the detail payload", %{actor: actor} do
    [summary | _] = run(:list_weaknesses, %{}, actor)
    detail = run(:get_weakness, %{"cwe_id" => 79}, actor)

    assert byte_size(Jason.encode!(summary)) * 10 < byte_size(Jason.encode!(detail))
  end
end
