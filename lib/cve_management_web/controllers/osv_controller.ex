# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.OsvController do
  use CveManagementWeb, :controller

  alias CveManagement.CVE

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
end
