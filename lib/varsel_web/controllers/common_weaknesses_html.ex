# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CommonWeaknessesHTML do
  @moduledoc """
  HTML rendering for the public CWE distribution browser
  (`VarselWeb.CommonWeaknessesController`): the view root (donut + legend +
  the embedded paged CVE table scoped to the whole view) and its per-CWE
  drill-down (donut + legend plus the same table, scoped to that one CWE
  subtree instead), both via `VarselWeb.CommonWeaknessesCveTableLive`.
  """
  use VarselWeb, :html

  import VarselWeb.ChartComponents, only: [cwe_donut: 1, cwe_legend: 1]

  embed_templates "common_weaknesses_html/*"

  @doc "JSON-safe live_render session for the drill-down's embedded CVE table."
  def table_session(view_id, cwe_id), do: %{"view_id" => view_id, "cwe_id" => cwe_id}
end
