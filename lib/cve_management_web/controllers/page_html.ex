# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.PageHTML do
  @moduledoc """
  This module contains pages rendered by PageController.

  See the `page_html` directory for all templates available.
  """
  use CveManagementWeb, :html

  alias CveManagementWeb.ChartComponents

  embed_templates "page_html/*"

  @doc "Short date for the homepage CVE cards."
  def format_home_date(nil), do: ""
  def format_home_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%b %-d, %Y")
end
