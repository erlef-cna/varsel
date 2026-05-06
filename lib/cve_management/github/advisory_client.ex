# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.GitHub.AdvisoryClient do
  @moduledoc """
  Low-level HTTP helpers for the GitHub REST advisory endpoints.
  """

  @base_url "https://api.github.com"
  @req_opts Keyword.take(Application.compile_env(:cve_management, :github_advisory, []), [:plug])

  @doc """
  Fetches a single advisory by its API URL.
  Returns `{:ok, advisory_map}` or `{:error, reason}`.
  """
  def fetch_advisory(access_token, url) do
    get_url(url, access_token)
  end

  @doc """
  Fetches repository security advisories (draft and triage states).
  Returns `{:ok, [advisory]}` or `{:error, reason}`.
  """
  def fetch_repository_advisories(access_token, owner, repo) do
    get("/repos/#{owner}/#{repo}/security-advisories", access_token)
  end

  @doc """
  Fetches organization security advisories.
  Returns `{:ok, [advisory]}` or `{:error, reason}`.
  """
  def fetch_org_advisories(access_token, org) do
    get("/orgs/#{org}/security-advisories", access_token)
  end

  defp get(path, access_token) do
    get_url("#{@base_url}#{path}", access_token)
  end

  defp get_url(url, access_token) do
    response =
      Req.get!(
        url,
        [
          headers: [
            authorization: "Bearer #{access_token}",
            accept: "application/vnd.github+json",
            "x-github-api-version": "2022-11-28"
          ]
        ] ++ @req_opts
      )

    case response.status do
      200 -> {:ok, response.body}
      401 -> {:error, :unauthorized}
      404 -> {:error, :not_found}
      status -> {:error, {:http_error, status}}
    end
  end
end
