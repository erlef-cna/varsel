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

  # Shape-only match for the reserved-but-unpublished 404: no CveRecord lookup
  # is allowed here (see render_404/2) — branching on a DB hit would make the
  # page an enumeration oracle for embargoed reservations.
  @cve_id_shape ~r/^CVE-\d{4}-\d{4,19}$/i

  # Machine-readable index of all published CVEs.
  def index(conn, _params) do
    query = Ash.Query.select(CVE.CveRecord, [:id])

    records =
      CVE.list_published_cve_records!(
        actor: nil,
        load: [:title, :date_published, :date_updated],
        strict?: true,
        query: query
      )

    render(conn, :index, records: records)
  end

  def show(conn, %{"cve_id" => cve_id} = params) do
    case Path.extname(cve_id) do
      ".json" -> show_json(conn, %{params | "cve_id" => Path.rootname(cve_id)})
      ".html" -> show_html(conn, %{params | "cve_id" => Path.rootname(cve_id)})
      _ -> render_404(conn, :html)
    end
  end

  def show_html(conn, %{"cve_id" => cve_id}) do
    record = CVE.get_published_cve_record!(cve_id, actor: nil)
    cve = record.cve_json
    cna = cve["containers"]["cna"] || %{}

    conn
    |> assign(:page_title, cve["cveMetadata"]["cveId"])
    |> render(:show, cve: cve, cna: cna, cwe_names: cwe_names(cna), capec_names: capec_names(cna))
  rescue
    Invalid -> render_404(conn, :html, cve_id)
  end

  def show_json(conn, %{"cve_id" => cve_id}) do
    query = Ash.Query.select(CVE.CveRecord, [:id, :cve_json])

    record =
      CVE.get_published_cve_record!(cve_id, actor: nil, query: query, load: [], strict?: true)

    json(conn, record.cve_json)
  rescue
    Invalid -> render_404(conn, :json)
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

  defp render_404(conn, format, cve_id \\ nil)

  defp render_404(conn, :html, cve_id) when is_binary(cve_id) do
    if Regex.match?(@cve_id_shape, cve_id) do
      conn
      |> put_status(:not_found)
      |> put_view(html: VarselWeb.ErrorHTML)
      |> render(:cve_404, cve_id: cve_id)
    else
      render_404(conn, :html, nil)
    end
  end

  defp render_404(conn, format, _cve_id) do
    conn
    |> put_status(:not_found)
    |> put_view(
      case format do
        :html -> [html: VarselWeb.ErrorHTML]
        :json -> [json: VarselWeb.ErrorJSON]
      end
    )
    |> render("404.#{format}")
  end
end
