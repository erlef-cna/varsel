# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveController do
  use VarselWeb, :controller

  alias Ash.Error.Invalid
  alias Varsel.CAPEC
  alias Varsel.CVE
  alias Varsel.CWE
  alias VarselWeb.CveView

  require Ash.Query

  # Machine-readable index of all published CVEs.
  def index(conn, _params) do
    records = CVE.list_published_cve_records!(actor: nil)
    render(conn, :index, records: records)
  end

  # HTML detail page (browser pipeline). A `.json` id (from `/cves/<id>.json`,
  # which also matches this single-segment route) is delegated to the JSON
  # renderer so both URLs keep working.
  def show_html(conn, %{"cve_id" => "index.json"}), do: conn |> put_format(:json) |> index(%{})

  def show_html(conn, %{"cve_id" => cve_id}) do
    if String.ends_with?(cve_id, ".json") do
      render_json(conn, String.replace_suffix(cve_id, ".json", ""))
    else
      record = CVE.get_published_cve_record!(cve_id, actor: nil)
      cve = record.cve_json
      cna = cve["containers"]["cna"] || %{}

      conn
      |> assign(:page_title, cve["cveMetadata"]["cveId"])
      |> render(:show,
        cve: cve,
        cna: cna,
        cwe_names: cwe_names(cna),
        capec_names: capec_names(cna)
      )
    end
  rescue
    Invalid ->
      conn
      |> put_status(:not_found)
      |> put_view(html: VarselWeb.ErrorHTML)
      |> render(:"404")
  end

  # id -> catalog name maps, one query each regardless of how many
  # CWE/CAPEC ids the record carries (N+1 safety).
  defp cwe_names(cna) do
    ids =
      cna
      |> CveView.cwe_descriptions()
      |> Enum.map(&CveView.cwe_id_number(&1["cweId"]))
      |> Enum.uniq()

    case ids do
      [] ->
        %{}

      _ids ->
        CWE.Weakness
        |> Ash.Query.select([:cwe_id, :name])
        |> Ash.Query.filter(cwe_id in ^ids)
        |> Ash.read!(actor: nil)
        |> Map.new(&{&1.cwe_id, &1.name})
    end
  end

  defp capec_names(cna) do
    ids =
      cna
      |> CveView.capec_items()
      |> Enum.map(&CveView.capec_id_number(&1["capecId"]))
      |> Enum.uniq()

    case ids do
      [] ->
        %{}

      _ids ->
        CAPEC.AttackPattern
        |> Ash.Query.select([:capec_id, :name])
        |> Ash.Query.filter(capec_id in ^ids)
        |> Ash.read!(actor: nil)
        |> Map.new(&{&1.capec_id, &1.name})
    end
  end

  # JSON record (api pipeline), also handles multi-segment wildcard paths.
  def show_json(conn, %{"path" => path}) do
    cve_id = path |> Enum.join("/") |> String.replace_suffix(".json", "")
    render_json(conn, cve_id)
  end

  defp render_json(conn, cve_id) do
    record = CVE.get_published_cve_record!(cve_id, actor: nil)
    json(conn, record.cve_json)
  rescue
    Invalid ->
      conn |> put_status(:not_found) |> json(%{})
  end
end
