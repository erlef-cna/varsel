# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.DevErrorPreviewController do
  @moduledoc """
  Dev-only preview of `VarselWeb.ErrorHTML` templates against a real status
  code, so the 401/403/404/500/generic-fallback states can be eyeballed in a
  browser without provoking the real condition.
  """
  use VarselWeb, :controller

  def show(conn, %{"status" => status}) do
    conn
    |> put_view(html: VarselWeb.ErrorHTML)
    |> render("#{status}.html")
  end
end
