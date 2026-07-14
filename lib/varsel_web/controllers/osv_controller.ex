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

  def show(conn, %{"path" => path}) do
    osv_id = path |> Enum.join("/") |> String.replace_suffix(".json", "")
    record = CVE.get_osv_record!(osv_id, actor: nil)
    json(conn, record.osv_json)
  rescue
    Ash.Error.Invalid ->
      conn |> put_status(:not_found) |> json(%{})
  end

  # `/osv/EEF-CVE-2025-1234` -> `/cves/CVE-2025-1234` (the Jekyll redirect).
  # A `.json` id keeps serving the raw OSV document via show/2 instead.
  def redirect_to_cve(conn, %{"osv_id" => "all.json"}), do: conn |> put_format(:json) |> index(%{})

  def redirect_to_cve(conn, %{"osv_id" => osv_id}) do
    if String.ends_with?(osv_id, ".json") do
      show(conn, %{"path" => [osv_id]})
    else
      case String.replace_prefix(osv_id, "EEF-", "") do
        ^osv_id -> conn |> put_status(:not_found) |> render_404()
        cve_id -> redirect(conn, to: ~p"/cves/#{cve_id}")
      end
    end
  end

  defp render_404(conn) do
    conn
    |> put_view(html: VarselWeb.ErrorHTML)
    |> render(:"404")
  end
end
