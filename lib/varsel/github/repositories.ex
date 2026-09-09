# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Repositories do
  @moduledoc """
  What a GitHub repository is to the user whose token is given: whether
  they administer it. A repository GitHub does not show them answers
  `:not_found`. A token GitHub no longer accepts answers
  `{:error, :unauthorized}`.
  """

  alias Varsel.GitHub.Client

  @type result :: {:ok, boolean()} | :not_found | {:error, :unauthorized | term()}

  @doc "Whether the user administers `owner/repo`, from the `permissions` GitHub reports for them on it."
  @spec admin?(String.t(), String.t(), token: String.t()) :: result()
  def admin?(owner, repo, opts) when is_binary(owner) and is_binary(repo) do
    [auth: {:bearer, Keyword.fetch!(opts, :token)}]
    |> Client.api()
    |> Req.get(url: "/repos/:owner/:repo", path_params: [owner: owner, repo: repo])
    |> case do
      {:ok, %Req.Response{status: 200, body: %{} = repository}} ->
        {:ok, get_in(repository, ["permissions", "admin"]) == true}

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
