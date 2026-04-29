# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.CveController do
  use CveManagementWeb, :controller

  alias CveManagement.CVE

  def index(conn, _params) do
    records = CVE.list_published_cve_records!(actor: nil)
    render(conn, :index, records: records)
  end

  def show(conn, %{"path" => path}) do
    cve_id = path |> Enum.join("/") |> String.replace_suffix(".json", "")
    record = CVE.get_published_cve_record!(cve_id, actor: nil)
    json(conn, record.cve_json)
  rescue
    Ash.Error.Invalid ->
      conn |> put_status(:not_found) |> json(%{})
  end
end
