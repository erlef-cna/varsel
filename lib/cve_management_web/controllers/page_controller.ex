# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.PageController do
  use CveManagementWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
