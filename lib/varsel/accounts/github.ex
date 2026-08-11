# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.GitHub do
  @moduledoc """
  Thin client for checking that a GitHub account exists.

  Unauthenticated, so subject to GitHub's low anonymous rate limit. Request
  options (a `Req.Test` plug in tests) come from `config :varsel, :github_api`.
  """

  @doc "Whether a GitHub account with this login exists, and its canonical spelling."
  @spec user(String.t()) :: {:ok, String.t()} | :not_found
  def user(login) when is_binary(login) do
    case Req.get!(build_req(), url: "/users/#{URI.encode(login)}") do
      %Req.Response{status: 200, body: %{"login" => canonical}} -> {:ok, canonical}
      %Req.Response{status: 404} -> :not_found
    end
  end

  defp build_req do
    Req.new(
      [
        base_url: "https://api.github.com",
        retry: false,
        headers: [{"accept", "application/vnd.github+json"}]
      ] ++ Application.get_env(:varsel, :github_api, [])
    )
  end
end
