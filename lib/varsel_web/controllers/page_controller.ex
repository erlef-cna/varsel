# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.PageController do
  use VarselWeb, :controller

  alias Varsel.CVE
  alias VarselWeb.Charts

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
    # %BASE_URL% lets compiled page bodies (e.g. the API samples on
    # /api-access) reference this deployment's own URL.
    page = Varsel.Content.get_page!(conn.assigns.page_id)
    body = String.replace(page.body, "%BASE_URL%", VarselWeb.Endpoint.url())
    render(conn, :page, page: %{page | body: body}, page_title: page.title)
  end
end
