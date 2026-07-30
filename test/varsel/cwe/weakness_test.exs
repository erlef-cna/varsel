# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.WeaknessTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Varsel.CWE.CweMetadata
  alias Varsel.CWE.CweXmlParser
  alias Varsel.CWE.View
  alias Varsel.CWE.ViewMembership
  alias Varsel.CWE.Weakness
  alias Varsel.CWE.WeaknessRelationship

  @sample_xml """
  <?xml version="1.0" encoding="UTF-8"?>
  <Weakness_Catalog>
    <Weaknesses>
      <Weakness ID="74" Name="Improper Neutralization of Special Elements in Output ('Injection')"
                Abstraction="Class" Status="Stable">
        <Description>The product constructs output using externally-influenced input.</Description>
      </Weakness>
      <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation"
                Abstraction="Base" Status="Stable">
        <Description>The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.</Description>
        <Extended_Description>This weakness is known as Cross-Site Scripting (XSS).</Extended_Description>
        <Related_Weaknesses>
          <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000" Ordinal="Primary"/>
          <Related_Weakness Nature="PeerOf" CWE_ID="80" View_ID="1000"/>
        </Related_Weaknesses>
        <Common_Consequences>
          <Consequence>
            <Scope>Confidentiality</Scope>
            <Impact>Read Application Data</Impact>
          </Consequence>
        </Common_Consequences>
        <Potential_Mitigations>
          <Mitigation>
            <Phase>Architecture and Design</Phase>
            <Description>Use a vetted library or framework that does not allow this weakness.</Description>
          </Mitigation>
        </Potential_Mitigations>
      </Weakness>
      <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
        <Description>Improper neutralization of special elements used in an SQL command.</Description>
        <Related_Weaknesses>
          <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000" Ordinal="Primary"/>
        </Related_Weaknesses>
      </Weakness>
    </Weaknesses>
    <Views>
      <View ID="1000" Name="Research Concepts" Type="Graph" Status="Draft">
        <Objective>This view is intended to facilitate research into weaknesses.</Objective>
        <Members>
          <Has_Member CWE_ID="79" View_ID="1000"/>
          <Has_Member CWE_ID="284" View_ID="1000"/>
        </Members>
      </View>
      <View ID="1040" Name="Quality Weaknesses with Indirect Security Impacts" Type="Implicit"
            Status="Incomplete">
        <Objective>CWE identifiers in this view (slice) are quality issues.</Objective>
        <Filter>/Weakness_Catalog/Weaknesses/Weakness[Weakness_Ordinalities/Weakness_Ordinality/Ordinality='Indirect']</Filter>
      </View>
    </Views>
  </Weakness_Catalog>
  """

  defp zip_xml(xml) do
    {:ok, {_name, zip_bytes}} =
      :zip.zip(~c"cwec_latest.xml", [{~c"cwec_latest.xml", xml}], [:memory])

    zip_bytes
  end

  defp stub_catalog(zip_bytes, last_modified \\ nil) do
    Req.Test.stub(Weakness, fn conn ->
      conn = Plug.Conn.fetch_query_params(conn)

      conn =
        if last_modified do
          Plug.Conn.put_resp_header(conn, "last-modified", last_modified)
        else
          conn
        end

      case conn.method do
        "GET" ->
          conn
          |> Plug.Conn.put_resp_content_type("application/zip")
          |> Plug.Conn.send_resp(200, zip_bytes)

        _ ->
          Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)
  end

  defp stub_catalog_not_modified(last_modified) do
    Req.Test.stub(Weakness, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("last-modified", last_modified)
      |> Plug.Conn.send_resp(304, "")
    end)
  end

  defp run_sync do
    Weakness
    |> Ash.ActionInput.for_action(:sync_cwe_catalog, %{}, authorize?: false)
    |> Ash.run_action!()
  end

  # Small chunks exercise XML tokens split across stream chunk boundaries.
  defp parse_weaknesses(xml) do
    xml |> Varsel.Xml.chunk_binary(64) |> CweXmlParser.stream_weaknesses() |> Enum.to_list()
  end

  defp parse_views(xml) do
    xml |> Varsel.Xml.chunk_binary(64) |> CweXmlParser.stream_views() |> Enum.to_list()
  end

  describe "CweXmlParser.stream_weaknesses/1" do
    test "parses all weaknesses from XML" do
      weaknesses = parse_weaknesses(@sample_xml)
      assert length(weaknesses) == 3
    end

    test "correctly parses CWE-79 attributes" do
      weaknesses = parse_weaknesses(@sample_xml)
      cwe79 = Enum.find(weaknesses, &(&1.cwe_id == 79))

      assert cwe79.name =~ "Improper Neutralization"
      assert cwe79.abstraction == :base
      assert cwe79.status == :stable
      assert cwe79.description =~ "user-controllable input"
      assert cwe79.extended_description =~ "Cross-Site Scripting"
    end

    test "parses related weaknesses with typed nature" do
      weaknesses = parse_weaknesses(@sample_xml)
      cwe79 = Enum.find(weaknesses, &(&1.cwe_id == 79))

      assert [
               %{nature: :child_of, target_cwe_id: 74, view_id: 1000, ordinal: "Primary"},
               %{nature: :peer_of, target_cwe_id: 80}
             ] =
               cwe79.related_weaknesses
    end

    test "parses mitigations concatenated with phase prefix" do
      weaknesses = parse_weaknesses(@sample_xml)
      cwe79 = Enum.find(weaknesses, &(&1.cwe_id == 79))

      assert cwe79.potential_mitigations =~ "Architecture and Design"
      assert cwe79.potential_mitigations =~ "vetted library"
    end

    test "parses common consequences with scope prefix" do
      weaknesses = parse_weaknesses(@sample_xml)
      cwe79 = Enum.find(weaknesses, &(&1.cwe_id == 79))

      assert cwe79.common_consequences =~ "Confidentiality"
      assert cwe79.common_consequences =~ "Read Application Data"
    end

    test "handles missing optional fields gracefully" do
      weaknesses = parse_weaknesses(@sample_xml)
      cwe74 = Enum.find(weaknesses, &(&1.cwe_id == 74))

      assert cwe74.related_weaknesses == []
      assert is_nil(cwe74.extended_description)
      assert is_nil(cwe74.potential_mitigations)
      assert is_nil(cwe74.common_consequences)
    end
  end

  describe "CweXmlParser.stream_views/1" do
    test "parses all views from XML" do
      views = parse_views(@sample_xml)
      assert length(views) == 2
    end

    test "parses a Graph view with members" do
      views = parse_views(@sample_xml)
      view = Enum.find(views, &(&1.view_id == 1000))

      assert view.name == "Research Concepts"
      assert view.type == :graph
      assert view.status == :draft
      assert view.objective =~ "facilitate research"
      assert view.members == [79, 284]
    end

    test "parses an Implicit slice view without members" do
      views = parse_views(@sample_xml)
      view = Enum.find(views, &(&1.view_id == 1040))

      assert view.name == "Quality Weaknesses with Indirect Security Impacts"
      assert view.type == :implicit_slice
      assert view.status == :incomplete
      assert view.members == []
    end
  end

  describe "sync_cwe_catalog action" do
    test "downloads, parses, and upserts all weaknesses" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      weaknesses = Ash.read!(Weakness, authorize?: false)
      assert length(weaknesses) == 3
    end

    test "is idempotent: running twice does not duplicate rows" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      assert Ash.count!(Weakness, authorize?: false) == 3
    end

    test "stores relationships with correct source and target" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      cwe79 =
        Ash.get!(Weakness, %{cwe_id: 79},
          load: [:related_weakness_relationships],
          authorize?: false
        )

      children =
        cwe79.related_weakness_relationships
        |> Enum.filter(&(&1.nature == :child_of))
        |> Enum.map(&{&1.source_cwe_id, &1.target_cwe_id})

      # CWE-79 ChildOf CWE-74 — the target must not be mis-assigned.
      assert children == [{79, 74}]
    end

    test "drops relationships whose target is not in the catalog" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      cwe79 =
        Ash.get!(Weakness, %{cwe_id: 79},
          load: [:related_weakness_relationships],
          authorize?: false
        )

      # CWE-79 PeerOf CWE-80, but CWE-80 is not in the sample catalog.
      refute Enum.any?(cwe79.related_weakness_relationships, &(&1.target_cwe_id == 80))
    end

    test "upserts views from the catalog" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      views =
        View
        |> Ash.read!(authorize?: false)
        |> Enum.map(&{&1.view_id, &1.name, &1.type, &1.status})
        |> Enum.sort()

      assert views == [
               {1000, "Research Concepts", :graph, :draft},
               {1040, "Quality Weaknesses with Indirect Security Impacts", :implicit_slice, :incomplete}
             ]
    end

    test "syncs view memberships, dropping members that are not weaknesses" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      memberships =
        ViewMembership
        |> Ash.read!(authorize?: false)
        |> Enum.map(&{&1.view_id, &1.cwe_id})
        |> Enum.sort()

      # Has_Member CWE_ID="284" is a Category, not a Weakness in the sample
      # catalog — it must be dropped, leaving only the 1000<->79 membership.
      assert memberships == [{1000, 79}]
    end

    # INT-006 regression: the relationship set is a snapshot of the catalog —
    # edges MITRE removed or reclassified must disappear, not accumulate.
    test "removes and reclassifies relationships across catalog versions" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      # v2: CWE-79's ChildOf 74 is reclassified to PeerOf; CWE-89 loses its
      # relationship entirely.
      v2_xml = """
      <?xml version="1.0" encoding="UTF-8"?>
      <Weakness_Catalog>
        <Weaknesses>
          <Weakness ID="74" Name="Injection" Abstraction="Class" Status="Stable">
            <Description>Parent class.</Description>
          </Weakness>
          <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>Cross-site scripting.</Description>
            <Related_Weaknesses>
              <Related_Weakness Nature="PeerOf" CWE_ID="74" View_ID="1000"/>
            </Related_Weaknesses>
          </Weakness>
          <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
            <Description>No relationships anymore.</Description>
          </Weakness>
        </Weaknesses>
        <Views>
          <View ID="1000" Name="Research Concepts" Type="Graph" Status="Draft">
            <Objective>This view is intended to facilitate research into weaknesses.</Objective>
            <Members>
              <Has_Member CWE_ID="74" View_ID="1000"/>
            </Members>
          </View>
        </Views>
      </Weakness_Catalog>
      """

      stub_catalog(zip_xml(v2_xml), "Fri, 01 May 2026 00:00:00 GMT")

      # The second sync runs through the real Oban path, so the diff's
      # deletes are exercised under production authorization (the join
      # resource's accessing_from policy, no bypass).
      assert %{success: 1, failure: 0} =
               AshOban.Test.schedule_and_run_triggers(
                 {Weakness, :sync_cwe_catalog},
                 scheduled_actions?: true,
                 triggers?: false
               )

      edges =
        WeaknessRelationship
        |> Ash.read!(authorize?: false)
        |> Enum.map(&{&1.source_cwe_id, &1.target_cwe_id, &1.nature, &1.view_id})
        |> Enum.sort()

      assert edges == [{79, 74, :peer_of, 1000}]

      # View 1040 (the Implicit slice) was dropped from the catalog.
      view_ids = View |> Ash.read!(authorize?: false) |> Enum.map(& &1.view_id) |> Enum.sort()
      assert view_ids == [1000]

      # Membership 1000<->79 was removed, 1000<->74 was added.
      memberships =
        ViewMembership
        |> Ash.read!(authorize?: false)
        |> Enum.map(&{&1.view_id, &1.cwe_id})
        |> Enum.sort()

      assert memberships == [{1000, 74}]
    end

    test "relationship writes outside the sync are forbidden" do
      assert {:error, %Forbidden{}} =
               Ash.create(
                 WeaknessRelationship,
                 %{source_cwe_id: 79, target_cwe_id: 74, nature: :child_of, view_id: 1000},
                 authorize?: true
               )
    end

    test "view membership writes outside the sync are forbidden" do
      assert {:error, %Forbidden{}} =
               Ash.create(
                 ViewMembership,
                 %{view_id: 1000, cwe_id: 79},
                 authorize?: true
               )
    end

    test "stores last-modified header in CweMetadata" do
      lm = "Thu, 30 Apr 2026 09:15:04 GMT"
      stub_catalog(zip_xml(@sample_xml), lm)
      run_sync()

      assert [%{last_modified: ^lm}] = Ash.read!(CweMetadata, authorize?: false)
    end

    test "skips download when server returns 304 Not Modified" do
      lm = "Thu, 30 Apr 2026 09:15:04 GMT"
      stub_catalog(zip_xml(@sample_xml), lm)
      run_sync()

      count_after_first = Ash.count!(Weakness, authorize?: false)

      stub_catalog_not_modified(lm)
      run_sync()

      assert Ash.count!(Weakness, authorize?: false) == count_after_first
    end

    test "sends If-Modified-Since header on subsequent requests" do
      lm = "Thu, 30 Apr 2026 09:15:04 GMT"
      stub_catalog(zip_xml(@sample_xml), lm)
      run_sync()

      test_pid = self()

      Req.Test.stub(Weakness, fn conn ->
        send(test_pid, {:headers, Plug.Conn.get_req_header(conn, "if-modified-since")})
        Plug.Conn.send_resp(conn, 304, "")
      end)

      run_sync()

      assert_received {:headers, [^lm]}
    end

    test "scheduled action runs via Oban" do
      stub_catalog(zip_xml(@sample_xml))

      assert %{success: 1, failure: 0} =
               AshOban.Test.schedule_and_run_triggers(
                 {Weakness, :sync_cwe_catalog},
                 scheduled_actions?: true,
                 triggers?: false
               )
    end
  end

  describe "get_by_cwe_id action" do
    setup do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()
      :ok
    end

    test "returns the correct weakness" do
      result =
        Weakness
        |> Ash.Query.for_read(:get_by_cwe_id, %{cwe_id: 79}, authorize?: false)
        |> Ash.read_one!()

      assert result.cwe_id == 79
      assert result.name =~ "Improper Neutralization"
    end

    test "returns nil for unknown CWE ID" do
      result =
        Weakness
        |> Ash.Query.for_read(:get_by_cwe_id, %{cwe_id: 9999}, authorize?: false)
        |> Ash.read_one()

      assert {:ok, nil} = result
    end
  end

  describe "search action" do
    setup do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()
      :ok
    end

    test "finds weakness by name keyword" do
      results =
        Weakness
        |> Ash.Query.for_read(:search, %{query: "injection"}, authorize?: false)
        |> Ash.read!(authorize?: false)

      assert Enum.any?(results, &(&1.cwe_id == 89))
    end

    test "finds weakness by description content" do
      results =
        Weakness
        |> Ash.Query.for_read(:search, %{query: "cross-site scripting"}, authorize?: false)
        |> Ash.read!(authorize?: false)

      assert Enum.any?(results, &(&1.cwe_id == 79))
    end

    test "returns empty list for unmatched query" do
      results =
        Weakness
        |> Ash.Query.for_read(:search, %{query: "qxzqxzqxz"}, authorize?: false)
        |> Ash.read!(authorize?: false)

      assert results == []
    end
  end
end
