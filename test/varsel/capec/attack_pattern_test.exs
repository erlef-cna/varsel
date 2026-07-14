# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.AttackPatternTest do
  use Varsel.DataCase, async: false

  alias Varsel.CAPEC.AttackPattern
  alias Varsel.CAPEC.AttackPatternWeakness
  alias Varsel.CAPEC.CapecMetadata
  alias Varsel.CAPEC.CapecXmlParser
  alias Varsel.CWE.CweMetadata
  alias Varsel.CWE.Weakness

  @sample_xml """
  <?xml version="1.0" encoding="UTF-8"?>
  <Attack_Pattern_Catalog>
    <Attack_Patterns>
      <Attack_Pattern ID="66" Name="SQL Injection" Abstraction="Meta" Status="Stable">
        <Description>An adversary exploits insufficient input validation to manipulate SQL queries.</Description>
        <Extended_Description>This is an extended description of SQL injection.</Extended_Description>
        <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
        <Typical_Severity>High</Typical_Severity>
        <Related_Attack_Patterns>
          <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="225"/>
          <Related_Attack_Pattern Nature="CanPrecede" CAPEC_ID="17"/>
        </Related_Attack_Patterns>
        <Related_Weaknesses>
          <Related_Weakness CWE_ID="89"/>
          <Related_Weakness CWE_ID="116"/>
        </Related_Weaknesses>
        <Prerequisites>
          <Prerequisite>The target application must interact with a SQL database.</Prerequisite>
          <Prerequisite>Input from the user is not properly validated.</Prerequisite>
        </Prerequisites>
        <Mitigations>
          <Mitigation>Use parameterized queries or prepared statements.</Mitigation>
          <Mitigation>Validate and sanitize all user-supplied input.</Mitigation>
        </Mitigations>
        <Consequences>
          <Consequence>
            <Scope>Confidentiality</Scope>
            <Scope>Integrity</Scope>
            <Impact>Read and modify database contents.</Impact>
          </Consequence>
          <Consequence>
            <Scope>Authorization</Scope>
            <Impact>Bypass authentication mechanisms.</Impact>
          </Consequence>
        </Consequences>
      </Attack_Pattern>
      <Attack_Pattern ID="7" Name="Blind SQL Injection" Abstraction="Detailed" Status="Draft">
        <Description>An adversary exploits blind SQL injection to infer data without direct output.</Description>
        <Related_Attack_Patterns/>
        <Related_Weaknesses/>
      </Attack_Pattern>
      <Attack_Pattern ID="100" Name="Overflow Buffers" Abstraction="Standard" Status="Deprecated">
        <Description>An adversary overflows a buffer with malicious data.</Description>
        <Related_Attack_Patterns/>
        <Related_Weaknesses/>
      </Attack_Pattern>
    </Attack_Patterns>
  </Attack_Pattern_Catalog>
  """

  defp stub_catalog(xml, last_modified \\ nil) do
    Req.Test.stub(AttackPattern, fn conn ->
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
          |> Plug.Conn.put_resp_content_type("application/xml")
          |> Plug.Conn.send_resp(200, xml)

        _ ->
          Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)
  end

  defp stub_catalog_not_modified(last_modified) do
    Req.Test.stub(AttackPattern, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("last-modified", last_modified)
      |> Plug.Conn.send_resp(304, "")
    end)
  end

  defp run_sync do
    Ash.create!(CweMetadata, %{}, action: :upsert, authorize?: false)

    AttackPattern
    |> Ash.ActionInput.for_action(:sync_capec_catalog, %{}, authorize?: false)
    |> Ash.run_action!()
  end

  defp seed_weaknesses(cwe_ids) do
    Enum.each(cwe_ids, fn id ->
      Ash.create!(
        Weakness,
        %{
          cwe_id: id,
          name: "CWE-#{id}",
          abstraction: :base,
          status: :stable,
          description: "Weakness #{id}"
        },
        action: :upsert,
        authorize?: false
      )
    end)
  end

  describe "CapecXmlParser.parse/1" do
    test "parses all attack patterns from XML" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      assert length(patterns) == 3
    end

    test "correctly parses CAPEC-66 attributes" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec66 = Enum.find(patterns, &(&1.capec_id == 66))

      assert capec66.name == "SQL Injection"
      assert capec66.abstraction == :meta
      assert capec66.status == :stable
      assert capec66.description =~ "insufficient input validation"
      assert capec66.extended_description =~ "extended description"
    end

    test "parses likelihood_of_attack and typical_severity" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec66 = Enum.find(patterns, &(&1.capec_id == 66))

      assert capec66.likelihood_of_attack == :high
      assert capec66.typical_severity == :high
    end

    test "parses related_attack_patterns with typed nature" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec66 = Enum.find(patterns, &(&1.capec_id == 66))

      assert [
               %{nature: :child_of, target_capec_id: 225},
               %{nature: :can_precede, target_capec_id: 17}
             ] = capec66.related_attack_patterns
    end

    test "parses related_weaknesses as list of integers" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec66 = Enum.find(patterns, &(&1.capec_id == 66))

      assert capec66.related_weaknesses == [89, 116]
    end

    test "parses prerequisites text" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec66 = Enum.find(patterns, &(&1.capec_id == 66))

      assert capec66.prerequisites =~ "SQL database"
      assert capec66.prerequisites =~ "not properly validated"
    end

    test "parses mitigations concatenated" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec66 = Enum.find(patterns, &(&1.capec_id == 66))

      assert capec66.mitigations =~ "parameterized queries"
      assert capec66.mitigations =~ "sanitize"
    end

    test "parses consequences with scope prefix" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec66 = Enum.find(patterns, &(&1.capec_id == 66))

      assert capec66.consequences =~ "Confidentiality"
      assert capec66.consequences =~ "Integrity"
      assert capec66.consequences =~ "database contents"
      assert capec66.consequences =~ "Authorization"
    end

    test "handles missing optional fields gracefully" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec7 = Enum.find(patterns, &(&1.capec_id == 7))

      assert capec7.related_attack_patterns == []
      assert capec7.related_weaknesses == []
      assert is_nil(capec7.extended_description)
      assert is_nil(capec7.likelihood_of_attack)
      assert is_nil(capec7.typical_severity)
      assert is_nil(capec7.prerequisites)
      assert is_nil(capec7.mitigations)
      assert is_nil(capec7.consequences)
    end

    test "parses deprecated status" do
      patterns = CapecXmlParser.parse!(@sample_xml)
      capec100 = Enum.find(patterns, &(&1.capec_id == 100))

      assert capec100.status == :deprecated
      assert capec100.abstraction == :standard
    end
  end

  describe "sync_capec_catalog action" do
    test "downloads, parses, and upserts all attack patterns" do
      stub_catalog(@sample_xml)
      run_sync()

      assert Ash.count!(AttackPattern, authorize?: false) == 3
    end

    test "is idempotent: running twice does not duplicate rows" do
      stub_catalog(@sample_xml)
      run_sync()
      stub_catalog(@sample_xml)
      run_sync()

      assert Ash.count!(AttackPattern, authorize?: false) == 3
    end

    test "stores last-modified header in CapecMetadata" do
      lm = "Thu, 30 Apr 2026 09:15:04 GMT"
      stub_catalog(@sample_xml, lm)
      run_sync()

      assert [%{last_modified: ^lm}] = Ash.read!(CapecMetadata, authorize?: false)
    end

    test "skips download when server returns 304 Not Modified" do
      lm = "Thu, 30 Apr 2026 09:15:04 GMT"
      stub_catalog(@sample_xml, lm)
      run_sync()

      count_after_first = Ash.count!(AttackPattern, authorize?: false)

      stub_catalog_not_modified(lm)
      run_sync()

      assert Ash.count!(AttackPattern, authorize?: false) == count_after_first
    end

    test "sends If-Modified-Since header on subsequent requests" do
      lm = "Thu, 30 Apr 2026 09:15:04 GMT"
      stub_catalog(@sample_xml, lm)
      run_sync()

      test_pid = self()

      Req.Test.stub(AttackPattern, fn conn ->
        send(test_pid, {:headers, Plug.Conn.get_req_header(conn, "if-modified-since")})
        Plug.Conn.send_resp(conn, 304, "")
      end)

      run_sync()

      assert_received {:headers, [^lm]}
    end

    test "scheduled action runs via Oban" do
      Ash.create!(CweMetadata, %{}, action: :upsert, authorize?: false)
      stub_catalog(@sample_xml)

      assert %{success: 1, failure: 0} =
               AshOban.Test.schedule_and_run_triggers(
                 {AttackPattern, :sync_capec_catalog},
                 scheduled_actions?: true,
                 triggers?: false
               )
    end
  end

  describe "weakness relationship (join table)" do
    test "populates join rows for weaknesses that exist in the CWE catalog" do
      seed_weaknesses([89, 116])
      stub_catalog(@sample_xml)
      run_sync()

      rows = Ash.read!(AttackPatternWeakness, authorize?: false)
      cwe_ids = rows |> Enum.map(& &1.cwe_id) |> Enum.sort()
      assert cwe_ids == [89, 116]
      assert Enum.all?(rows, &(&1.capec_id == 66))
    end

    test "does not create join rows for weaknesses absent from the CWE catalog" do
      seed_weaknesses([89])
      stub_catalog(@sample_xml)
      run_sync()

      rows = Ash.read!(AttackPatternWeakness, authorize?: false)
      assert length(rows) == 1
      assert hd(rows).cwe_id == 89
    end

    test "loads weaknesses relationship on attack pattern" do
      seed_weaknesses([89, 116])
      stub_catalog(@sample_xml)
      run_sync()

      pattern =
        AttackPattern
        |> Ash.Query.for_read(:get_by_capec_id, %{capec_id: 66}, authorize?: false)
        |> Ash.Query.load(:weaknesses)
        |> Ash.read_one!(authorize?: false)

      cwe_ids = pattern.weaknesses |> Enum.map(& &1.cwe_id) |> Enum.sort()
      assert cwe_ids == [89, 116]
    end
  end

  describe "get_by_capec_id action" do
    setup do
      stub_catalog(@sample_xml)
      run_sync()
      :ok
    end

    test "returns the correct attack pattern" do
      result =
        AttackPattern
        |> Ash.Query.for_read(:get_by_capec_id, %{capec_id: 66}, authorize?: false)
        |> Ash.read_one!()

      assert result.capec_id == 66
      assert result.name == "SQL Injection"
    end

    test "returns nil for unknown CAPEC ID" do
      result =
        AttackPattern
        |> Ash.Query.for_read(:get_by_capec_id, %{capec_id: 9999}, authorize?: false)
        |> Ash.read_one()

      assert {:ok, nil} = result
    end
  end

  describe "search action" do
    setup do
      stub_catalog(@sample_xml)
      run_sync()
      :ok
    end

    test "finds attack pattern by name keyword" do
      results =
        AttackPattern
        |> Ash.Query.for_read(:search, %{query: "injection"}, authorize?: false)
        |> Ash.read!(authorize?: false)

      assert Enum.any?(results, &(&1.capec_id == 66))
    end

    test "finds attack pattern by description content" do
      results =
        AttackPattern
        |> Ash.Query.for_read(:search, %{query: "blind sql"}, authorize?: false)
        |> Ash.read!(authorize?: false)

      assert Enum.any?(results, &(&1.capec_id == 7))
    end

    test "returns empty list for unmatched query" do
      results =
        AttackPattern
        |> Ash.Query.for_read(:search, %{query: "qxzqxzqxz"}, authorize?: false)
        |> Ash.read!(authorize?: false)

      assert results == []
    end
  end
end
