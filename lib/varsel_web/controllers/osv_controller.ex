# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.OsvController do
  use VarselWeb, :controller

  alias Varsel.CVE

  def index(conn, _params) do
    records = CVE.list_osv_feed!(actor: nil)
    render(conn, :index, records: records)
  end

  def show(conn, %{"osv_id" => osv_id} = params) do
    case Path.extname(osv_id) do
      ".json" -> show_json(conn, %{params | "osv_id" => Path.rootname(osv_id)})
      ".html" -> redirect_to_cve(conn, %{params | "osv_id" => Path.rootname(osv_id)})
      _ -> render_404(conn, :html)
    end
  end

  defp show_json(conn, %{"osv_id" => osv_id}) do
    record = CVE.get_osv_record!(osv_id, actor: nil)
    json(conn, record.osv_json)
  rescue
    Ash.Error.Invalid ->
      render_404(conn, :json)
  end

  defp redirect_to_cve(conn, params)

  defp redirect_to_cve(conn, %{"osv_id" => "EEF-" <> cve_id}) do
    conn
    |> put_status(:moved_permanently)
    |> redirect(to: ~p"/cves/#{cve_id <> ".html"}")
  end

  defp redirect_to_cve(conn, _params) do
    render_404(conn, :html)
  end

  defp render_404(conn, format) do
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
