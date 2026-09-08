# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Client do
  @moduledoc """
  Builds every request Varsel sends to the GitHub REST API.

  `api/1` merges `config :varsel, :github_api`, which is where tests swap
  the transport for a plug.
  """

  @api_version "2022-11-28"

  @doc """
  A request to `api.github.com`. `opts` are Req options, `auth:` above all.
  """
  @spec api(keyword()) :: Req.Request.t()
  def api(opts \\ []) do
    Req.new(
      [
        base_url: "https://api.github.com",
        retry: false,
        headers: [
          {"accept", "application/vnd.github+json"},
          {"x-github-api-version", @api_version}
        ]
      ] ++ opts ++ transport()
    )
  end

  defp transport, do: Application.get_env(:varsel, :github_api, [])
end
