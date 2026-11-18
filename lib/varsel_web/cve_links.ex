# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveLinks do
  @moduledoc """
  The absolute URLs of a published CVE's page and of its JSON forms, as
  search engines are told about them: the HTML page is canonical, and the CVE
  record and the OSV record are its alternates.
  """

  use VarselWeb, :verified_routes

  @doc "The canonical URL of the page of `cve_id`, on the configured host."
  @spec html_url(String.t()) :: String.t()
  def html_url(cve_id), do: url(~p"/cves/#{cve_id <> ".html"}")

  @doc """
  Names the page of `cve_id` as the canonical form of the response, in a
  `Link` header. Search engines read it on responses that are not HTML.
  """
  @spec put_canonical(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def put_canonical(conn, cve_id) do
    Plug.Conn.put_resp_header(conn, "link", ~s(<#{html_url(cve_id)}>; rel="canonical"))
  end

  @doc """
  The alternate formats of the page of `cve_id`, for the root layout: the CVE
  record, and the OSV record when there is one.
  """
  @spec alternates(String.t(), %{osv_id: String.t()} | nil) :: [
          %{href: String.t(), type: String.t()}
        ]
  def alternates(cve_id, osv_record) do
    cve = %{href: url(~p"/cves/#{cve_id <> ".json"}"), type: "application/json"}

    case osv_record do
      %{osv_id: osv_id} ->
        [cve, %{href: url(~p"/osv/#{osv_id <> ".json"}"), type: "application/json"}]

      nil ->
        [cve]
    end
  end
end
