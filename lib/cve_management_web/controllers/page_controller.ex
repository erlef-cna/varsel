# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.PageController do
  use CveManagementWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end

  def page(conn, _params) do
    page = CveManagement.Content.get_page!(conn.assigns.page_id)
    render(conn, :page, page: page, page_title: page.title)
  end
end
