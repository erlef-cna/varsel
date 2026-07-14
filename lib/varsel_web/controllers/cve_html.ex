# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveHTML do
  @moduledoc """
  HTML rendering for CVE detail pages. The Phoenix port of the Jekyll site's
  `_layouts/cve.html`; per-field link/format logic lives in
  `VarselWeb.CveView`.
  """
  use VarselWeb, :html

  import VarselWeb.CveView

  embed_templates "cve_html/*"

  @doc "Rows for the components table: zips modules / files / routines by index."
  def component_rows(entry) do
    modules = entry["modules"] || []
    files = entry["programFiles"] || []
    routines = entry["programRoutines"] || []
    max = Enum.max([length(modules), length(files), length(routines), 0])

    for i <- 0..(max - 1)//1 do
      %{
        module: Enum.at(modules, i),
        file: Enum.at(files, i),
        routine: get_in(Enum.at(routines, i) || %{}, ["name"])
      }
    end
  end

  @doc "Whether an affected entry needs the Changes / Fixed-in column."
  def any_changes?(entry) do
    Enum.any?(entry["versions"] || [], fn v ->
      (v["changes"] || []) != [] or Map.has_key?(v, "lessThan")
    end)
  end

  @doc "Info-link explaining a version type's ordering, or nil."
  def version_type_info("otp"),
    do: {"https://www.erlang.org/doc/system/versions.html#order-of-versions", "OTP version ordering"}

  def version_type_info("git"),
    do:
      {"https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md#source-control-versions",
       "Git version scheme"}

  def version_type_info("semver"), do: {"https://semver.org/", "Semantic Versioning"}
  def version_type_info(_other), do: nil

  @doc "References worth showing: drops version-scheme tags and self-links."
  def visible_references(cna, self_url) do
    cna
    |> Map.get("references", [])
    |> Enum.reject(fn ref ->
      "x_version-scheme" in (ref["tags"] || []) or ref["url"] == self_url
    end)
  end
end
