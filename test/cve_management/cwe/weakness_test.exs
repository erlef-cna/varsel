# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CWE.WeaknessTest do
  use CveManagement.DataCase, async: false

  alias CveManagement.CWE.CweMetadata
  alias CveManagement.CWE.CweXmlParser
  alias CveManagement.CWE.Weakness

  @sample_xml """
  <?xml version="1.0" encoding="UTF-8"?>
  <Weakness_Catalog>
    <Weaknesses>
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
        <Related_Weaknesses/>
      </Weakness>
    </Weaknesses>
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

  describe "CweXmlParser.parse/1" do
    test "parses all weaknesses from XML" do
      {:ok, weaknesses} = CweXmlParser.parse(@sample_xml)
      assert length(weaknesses) == 2
    end

    test "correctly parses CWE-79 attributes" do
      {:ok, weaknesses} = CweXmlParser.parse(@sample_xml)
      cwe79 = Enum.find(weaknesses, &(&1.cwe_id == 79))

      assert cwe79.name =~ "Improper Neutralization"
      assert cwe79.abstraction == :base
      assert cwe79.status == :stable
      assert cwe79.description =~ "user-controllable input"
      assert cwe79.extended_description =~ "Cross-Site Scripting"
    end

    test "parses related weaknesses with typed nature" do
      {:ok, weaknesses} = CweXmlParser.parse(@sample_xml)
      cwe79 = Enum.find(weaknesses, &(&1.cwe_id == 79))

      assert [
               %{nature: :child_of, cwe_id: 74, view_id: 1000, ordinal: "Primary"},
               %{nature: :peer_of, cwe_id: 80}
             ] =
               cwe79.related_weaknesses
    end

    test "parses mitigations concatenated with phase prefix" do
      {:ok, weaknesses} = CweXmlParser.parse(@sample_xml)
      cwe79 = Enum.find(weaknesses, &(&1.cwe_id == 79))

      assert cwe79.potential_mitigations =~ "Architecture and Design"
      assert cwe79.potential_mitigations =~ "vetted library"
    end

    test "parses common consequences with scope prefix" do
      {:ok, weaknesses} = CweXmlParser.parse(@sample_xml)
      cwe79 = Enum.find(weaknesses, &(&1.cwe_id == 79))

      assert cwe79.common_consequences =~ "Confidentiality"
      assert cwe79.common_consequences =~ "Read Application Data"
    end

    test "handles missing optional fields gracefully" do
      {:ok, weaknesses} = CweXmlParser.parse(@sample_xml)
      cwe89 = Enum.find(weaknesses, &(&1.cwe_id == 89))

      assert cwe89.related_weaknesses == []
      assert is_nil(cwe89.extended_description)
      assert is_nil(cwe89.potential_mitigations)
      assert is_nil(cwe89.common_consequences)
    end
  end

  describe "sync_cwe_catalog action" do
    test "downloads, parses, and upserts all weaknesses" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      weaknesses = Ash.read!(Weakness, authorize?: false)
      assert length(weaknesses) == 2
    end

    test "is idempotent: running twice does not duplicate rows" do
      stub_catalog(zip_xml(@sample_xml))
      run_sync()
      stub_catalog(zip_xml(@sample_xml))
      run_sync()

      assert Ash.count!(Weakness, authorize?: false) == 2
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
