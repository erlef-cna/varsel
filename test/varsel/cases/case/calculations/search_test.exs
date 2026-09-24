# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.SearchTest do
  use Varsel.DataCase, async: true

  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case
  alias Varsel.Fixtures

  require Ash.Query

  setup do
    %{poc: Fixtures.register_user("search_poc", :poc)}
  end

  defp titles(term, actor) do
    Case
    |> Ash.Query.filter(matches_query(query: ^String.downcase(term)))
    |> Ash.read!(actor: actor)
    |> Enum.map(& &1.title)
  end

  defp rank(case_record, term, actor) do
    Case
    |> Ash.Query.filter(id == ^case_record.id)
    |> Ash.Query.load(search_rank: [query: String.downcase(term)])
    |> Ash.read_one!(actor: actor)
    |> Map.fetch!(:search_rank)
  end

  describe "matches_query — the case's own text" do
    test "matches the title and the body, and stems both", %{poc: poc} do
      Fixtures.open_case(poc, %{title: "Request smuggling", description_md: "It smuggles."})
      Fixtures.open_case(poc, %{title: "Unrelated"})

      assert titles("smuggling", poc) == ["Request smuggling"]
      # The stemmer reaches the title from a different surface form.
      assert titles("smuggle", poc) == ["Request smuggling"]
    end

    test "a half-typed word still finds its case", %{poc: poc} do
      Fixtures.open_case(poc, %{title: "Bandit request smuggling"})

      assert titles("bandi", poc) == ["Bandit request smuggling"]
    end

    test "ignores case", %{poc: poc} do
      Fixtures.open_case(poc, %{title: "Bandit"})

      assert titles("BANDIT", poc) == ["Bandit"]
    end
  end

  describe "matches_query — affected packages" do
    setup %{poc: poc} do
      tagged = Fixtures.open_case(poc, %{title: "No hint in the title"})
      Fixtures.add_affected_package(poc, tagged, %{vendor: "acme", product: "my_library"})
      Fixtures.open_case(poc, %{title: "Unrelated"})

      %{tagged: tagged}
    end

    test "the whole package name matches, underscore and all", %{poc: poc} do
      assert titles("my_library", poc) == ["No hint in the title"]
    end

    test "so does a part of it", %{poc: poc} do
      assert titles("library", poc) == ["No hint in the title"]
    end

    test "a case is as findable by its vendor as by its product", %{poc: poc} do
      assert titles("acme", poc) == ["No hint in the title"]
    end
  end

  describe "matches_query — the CVE record" do
    test "matches the assigned CVE ID", %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Has an ID"})
      record = Fixtures.reserved_cve_record("CVE-2026-40010")
      Cases.assign_case_cve_id!(case_record, %{cve_record_id: record.id}, actor: poc)

      assert titles("CVE-2026-40010", poc) == ["Has an ID"]
    end

    test "matches the published record's own words", %{poc: poc} do
      record = Fixtures.published_cve_record("CVE-2026-40011", "Heap overflow in libfoo")
      adopted = Cases.adopt_cve_record!(%{cve_record_id: record.id}, actor: poc)
      Cases.edit_case!(adopted, %{title: "Says nothing useful"}, actor: poc)

      # The word appears only in the published record, not on the case.
      assert titles("libfoo", poc) == ["Says nothing useful"]
    end
  end

  describe "matches_query — the case id" do
    test "matches the whole UUID and its leading segment", %{poc: poc} do
      target = Fixtures.open_case(poc, %{title: "Found by id"})
      Fixtures.open_case(poc, %{title: "Unrelated"})

      assert titles(target.id, poc) == ["Found by id"]

      [leading | _] = String.split(target.id, "-")
      assert titles(leading, poc) == ["Found by id"]
    end

    # `30e75d15` parses as scientific notation, which used to split the lexeme
    # and leave the id unmatchable. Around one id in twenty looks like this,
    # so a random one only catches it sometimes.
    test "matches an id whose segment reads as a number", %{poc: poc} do
      id = "30e75d15-d1e3-4626-adbe-a0be5359d245"
      Ash.Seed.seed!(Case, %{id: id, title: "Numeric id", state: :draft})

      assert titles(id, poc) == ["Numeric id"]
      assert titles("30e75d15", poc) == ["Numeric id"]
    end
  end

  describe "matches_query — no match" do
    test "a term nothing carries returns nothing", %{poc: poc} do
      Fixtures.open_case(poc, %{title: "Bandit"})

      assert titles("cowboy", poc) == []
    end
  end

  describe "search_rank" do
    test "a title hit outranks a body mention, which outranks a package-only hit", %{poc: poc} do
      titled = Fixtures.open_case(poc, %{title: "bandit request smuggling"})
      bodied = Fixtures.open_case(poc, %{title: "Unrelated", description_md: "Mentions bandit."})
      packaged = Fixtures.open_case(poc, %{title: "Nothing here"})
      Fixtures.add_affected_package(poc, packaged, %{vendor: "acme", product: "bandit"})

      assert rank(titled, "bandit", poc) > rank(bodied, "bandit", poc)
      assert rank(bodied, "bandit", poc) > rank(packaged, "bandit", poc)
    end

    test "a case with neither packages nor a CVE record still ranks", %{poc: poc} do
      bare = Fixtures.open_case(poc, %{title: "Bandit"})

      # Every vector but the case's own is NULL here; an uncoalesced `||`
      # would make the whole rank NULL.
      assert rank(bare, "bandit", poc) > 0
    end

    test "a term the case does not carry ranks zero", %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Bandit"})

      assert rank(case_record, "cowboy", poc) == 0.0
    end
  end

  describe "the search vectors" do
    test "a package vector follows its row", %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "No hint"})
      package = Fixtures.add_affected_package(poc, case_record, %{product: "bandit"})

      assert titles("bandit", poc) == ["No hint"]

      Cases.edit_affected_package!(package, %{product: "cowboy"}, actor: poc)

      assert titles("bandit", poc) == []
      assert titles("cowboy", poc) == ["No hint"]
    end

    test "a case vector follows its row", %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "Before"})

      assert titles("before", poc) == ["Before"]

      Cases.edit_case!(case_record, %{title: "After"}, actor: poc)

      assert titles("before", poc) == []
      assert titles("after", poc) == ["After"]
    end

    test "a removed package stops matching", %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "No hint"})
      package = Fixtures.add_affected_package(poc, case_record, %{product: "bandit"})

      Cases.remove_affected_package!(package, actor: poc)

      assert titles("bandit", poc) == []
    end
  end

  describe "authorization" do
    test "search cannot reach a case the actor may not read", %{poc: poc} do
      supporter = Fixtures.register_user("search_supporter", :supporter)
      Fixtures.open_case(poc, %{title: "POC only bandit"})

      assert titles("bandit", poc) == ["POC only bandit"]
      assert titles("bandit", supporter) == []
    end
  end

  test "a read does not select the search vectors", %{poc: poc} do
    case_record = Fixtures.open_case(poc, %{title: "Bandit"})
    Fixtures.add_affected_package(poc, case_record, %{product: "bandit"})

    assert [%{search_vector: %Ash.NotLoaded{}}] = Ash.read!(Case, actor: poc)

    assert [%{search_vector: %Ash.NotLoaded{}}] =
             Ash.read!(AffectedPackage, authorize?: false)
  end
end
