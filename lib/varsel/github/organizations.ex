# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Organizations do
  @moduledoc """
  Who is who in a GitHub organization: its owners and a team's members, by
  login, as the user whose token is given. GitHub answers for a member of
  the organization holding the `read:org` scope. A token GitHub no longer
  accepts answers `{:error, :unauthorized}`.
  """

  alias Varsel.GitHub.Client

  @type result :: {:ok, [String.t()]} | :not_found | {:error, :unauthorized | term()}

  @doc "The logins of `org`'s owners. `:not_found` for an account that is no organization."
  @spec owners(String.t(), token: String.t()) :: result()
  def owners(org, opts) when is_binary(org) do
    logins(opts,
      url: "/orgs/:org/members",
      path_params: [org: org],
      params: [role: "admin", per_page: 100]
    )
  end

  @doc "The logins of the members of team `slug` in `org`."
  @spec team_members(String.t(), String.t(), token: String.t()) :: result()
  def team_members(org, slug, opts) when is_binary(org) and is_binary(slug) do
    logins(opts,
      url: "/orgs/:org/teams/:slug/members",
      path_params: [org: org, slug: slug],
      params: [per_page: 100]
    )
  end

  defp logins(opts, request_opts) do
    [auth: {:bearer, Keyword.fetch!(opts, :token)}]
    |> Client.api()
    |> Req.get(request_opts)
    |> case do
      {:ok, %Req.Response{status: 200, body: members}} when is_list(members) ->
        {:ok, for(%{"login" => login} <- members, is_binary(login), do: login)}

      {:ok, %Req.Response{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %Req.Response{status: 404}} ->
        :not_found

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, {:http, status, body}}

      {:error, exception} ->
        {:error, exception}
    end
  end
end
