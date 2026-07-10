# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.PageController do
  use CveManagementWeb, :controller

  alias CveManagement.CVE
  alias CveManagementWeb.Charts

  def home(conn, _params) do
    latest =
      [load: [:cve_id, :title, :date_published, :purls], actor: nil]
      |> CVE.list_published_cve_records!()
      |> Enum.take(3)

    render(conn, :home,
      activity_data: Charts.cve_activity_data(),
      latest: latest
    )
  end

  def page(conn, _params) do
    page = CveManagement.Content.get_page!(conn.assigns.page_id)
    render(conn, :page, page: page, page_title: page.title)
  end
end
