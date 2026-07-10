# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.CveController do
  use CveManagementWeb, :controller

  alias Ash.Error.Invalid
  alias CveManagement.CVE

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

      conn
      |> assign(:page_title, cve["cveMetadata"]["cveId"])
      |> render(:show, cve: cve, cna: cve["containers"]["cna"] || %{})
    end
  rescue
    Invalid ->
      conn
      |> put_status(:not_found)
      |> put_view(html: CveManagementWeb.ErrorHTML)
      |> render(:"404")
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
