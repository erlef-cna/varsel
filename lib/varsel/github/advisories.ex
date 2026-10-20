# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Advisories do
  @moduledoc """
  GitHub security advisories over the REST API: reading a repository's own
  advisory or the global database entry, updating one, reporting one
  privately, reading and writing the comments on one, and the forms a GHSA
  is pasted in.

  A read runs as the holder of the token given, a person or the App. That is
  what lets GitHub decide whether a draft is theirs to see: a draft they may
  not see answers 404, the same as an advisory that does not exist. Without
  a token only published advisories on public repositories answer. Writes
  always carry a token: GitHub attributes them to its holder and decides
  whether they may. `Varsel.GitHub.Credentials` decides which token. A token
  GitHub no longer accepts answers `{:error, :unauthorized}`.
  """

  alias Varsel.GitHub.Client

  # A GHSA id is `GHSA-` and three groups of four from GitHub's alphabet.
  @ghsa_id ~r/\AGHSA(-[23456789cfghjmpqrvwx]{4}){3}\z/i

  @typedoc """
  Where an advisory lives: on a repository, or only in the global database
  when the input named no repository.
  """
  @type ref ::
          %{ghsa_id: String.t(), owner: String.t(), repo: String.t()} | %{ghsa_id: String.t()}

  @type result :: {:ok, map()} | :not_found | {:error, :unauthorized | term()}

  @doc """
  Reads a pasted advisory address: a bare GHSA id, a repository advisory URL
  (`https://github.com/<owner>/<repo>/security/advisories/GHSA-…`) or a global
  one (`https://github.com/advisories/GHSA-…`).
  """
  @spec parse(String.t()) :: {:ok, ref()} | :error
  def parse(input) when is_binary(input) do
    input = String.trim(input)

    if ghsa_id?(input), do: {:ok, %{ghsa_id: normalize_id(input)}}, else: parse_url(input)
  end

  @doc """
  The advisory `ghsa_id` of `owner/repo`. `token:` is the acting user's GitHub
  token; without it the read is anonymous.
  """
  @spec fetch(String.t(), String.t(), String.t(), token: String.t() | nil) :: result()
  def fetch(owner, repo, ghsa_id, opts \\ []) when is_binary(owner) and is_binary(repo) and is_binary(ghsa_id) do
    request(Keyword.get(opts, :token),
      url: "/repos/:owner/:repo/security-advisories/:ghsa_id",
      path_params: [owner: owner, repo: repo, ghsa_id: ghsa_id]
    )
  end

  @doc "The global advisory database entry for `ghsa_id`. Published advisories only."
  @spec fetch_global(String.t(), token: String.t() | nil) :: result()
  def fetch_global(ghsa_id, opts \\ []) when is_binary(ghsa_id) do
    request(Keyword.get(opts, :token),
      url: "/advisories/:ghsa_id",
      path_params: [ghsa_id: ghsa_id]
    )
  end

  @doc """
  Whether `owner/repo` accepts private vulnerability reports. Answered for
  any repository the token can see.
  """
  @spec private_reporting_enabled?(String.t(), String.t(), token: String.t() | nil) ::
          {:ok, boolean()} | :not_found | {:error, term()}
  def private_reporting_enabled?(owner, repo, opts \\ []) when is_binary(owner) and is_binary(repo) do
    case request(Keyword.get(opts, :token),
           url: "/repos/:owner/:repo/private-vulnerability-reporting",
           path_params: [owner: owner, repo: repo]
         ) do
      {:ok, %{"enabled" => enabled}} when is_boolean(enabled) -> {:ok, enabled}
      {:ok, body} -> {:error, {:unexpected, body}}
      other -> other
    end
  end

  @doc """
  Updates the advisory `ghsa_id` of `owner/repo` with `body`, the fields of
  GitHub's update request, as the holder of the token given. Answers the
  advisory as it now stands.
  """
  @spec update(String.t(), String.t(), String.t(), map(), token: String.t()) :: result()
  def update(owner, repo, ghsa_id, body, opts)
      when is_binary(owner) and is_binary(repo) and is_binary(ghsa_id) and is_map(body) do
    request(Keyword.fetch!(opts, :token),
      method: :patch,
      url: "/repos/:owner/:repo/security-advisories/:ghsa_id",
      path_params: [owner: owner, repo: repo, ghsa_id: ghsa_id],
      json: body
    )
  end

  @doc """
  Opens a draft advisory on `owner/repo` with the token given: one of a
  person who administers the repository, or the App's installation token on
  it. Answers the draft.
  """
  @spec create(String.t(), String.t(), map(), token: String.t()) :: result()
  def create(owner, repo, body, opts) when is_binary(owner) and is_binary(repo) and is_map(body) do
    request(Keyword.fetch!(opts, :token),
      method: :post,
      url: "/repos/:owner/:repo/security-advisories",
      path_params: [owner: owner, repo: repo],
      json: body
    )
  end

  @doc """
  Reports a vulnerability privately to the maintainers of `owner/repo`, as
  the user whose token is given. Answers the advisory GitHub opened for it.
  """
  @spec report(String.t(), String.t(), map(), token: String.t()) :: result()
  def report(owner, repo, body, opts) when is_binary(owner) and is_binary(repo) and is_map(body) do
    request(Keyword.fetch!(opts, :token),
      method: :post,
      url: "/repos/:owner/:repo/security-advisories/reports",
      path_params: [owner: owner, repo: repo],
      json: body
    )
  end

  @doc """
  The comments on the advisory `ghsa_id` of `owner/repo`, oldest first.

  `since:` limits the answer to the comments written or edited at or after
  that moment, which is how a poll asks only for what it has not read.
  GitHub answers an empty list to a caller who may see the advisory but not
  its discussion, so an empty list never means the discussion is empty.
  Confidential comments are never answered.
  """
  @spec list_comments(String.t(), String.t(), String.t(),
          token: String.t() | nil,
          since: DateTime.t() | nil
        ) ::
          {:ok, [map()]} | :not_found | {:error, :unauthorized | term()}
  def list_comments(owner, repo, ghsa_id, opts \\ []) when is_binary(owner) and is_binary(repo) and is_binary(ghsa_id) do
    params =
      Enum.reject([per_page: 100, since: since_param(opts[:since])], &match?({_key, nil}, &1))

    opts
    |> Keyword.get(:token)
    |> req()
    |> Req.request(
      method: :get,
      url: "/repos/:owner/:repo/security-advisories/:ghsa_id/comments",
      path_params: [owner: owner, repo: repo, ghsa_id: ghsa_id],
      params: params
    )
    |> case do
      {:ok, %Req.Response{status: 200, body: comments}} when is_list(comments) -> {:ok, comments}
      other -> translate(other)
    end
  end

  @doc """
  Writes `body` as a comment on the advisory `ghsa_id` of `owner/repo`, as
  the holder of the token given. Answers the comment GitHub recorded.
  """
  @spec post_comment(String.t(), String.t(), String.t(), String.t(), token: String.t()) ::
          result()
  def post_comment(owner, repo, ghsa_id, body, opts)
      when is_binary(owner) and is_binary(repo) and is_binary(ghsa_id) and is_binary(body) do
    request(Keyword.fetch!(opts, :token),
      method: :post,
      url: "/repos/:owner/:repo/security-advisories/:ghsa_id/comments",
      path_params: [owner: owner, repo: repo, ghsa_id: ghsa_id],
      json: %{body: body}
    )
  end

  defp since_param(nil), do: nil
  defp since_param(%DateTime{} = since), do: DateTime.to_iso8601(since)

  defp request(token, request_opts) do
    token
    |> req()
    |> Req.request(Keyword.put_new(request_opts, :method, :get))
    |> case do
      {:ok, %Req.Response{status: status, body: %{} = body}} when status in [200, 201] ->
        {:ok, body}

      other ->
        translate(other)
    end
  end

  defp translate({:ok, %Req.Response{status: 401}}), do: {:error, :unauthorized}
  defp translate({:ok, %Req.Response{status: 404}}), do: :not_found

  defp translate({:ok, %Req.Response{status: status, body: body}}), do: {:error, {:http, status, body}}

  defp translate({:error, exception}), do: {:error, exception}

  defp req(nil), do: Client.api()
  defp req(token) when is_binary(token), do: Client.api(auth: {:bearer, token})

  defp ghsa_id?(value), do: Regex.match?(@ghsa_id, value)

  defp parse_url(input) do
    with %URI{scheme: scheme, host: "github.com", path: path}
         when scheme in ["https", "http"] and is_binary(path) <- URI.parse(input),
         {:ok, ref} <- path |> String.split("/", trim: true) |> from_segments() do
      {:ok, ref}
    else
      _not_an_advisory_url -> :error
    end
  end

  defp from_segments(["advisories", id]), do: ref(%{}, id)

  defp from_segments([owner, repo, "security", "advisories", id]), do: ref(%{owner: owner, repo: repo}, id)

  defp from_segments(_segments), do: :error

  defp ref(base, id) do
    if ghsa_id?(id), do: {:ok, Map.put(base, :ghsa_id, normalize_id(id))}, else: :error
  end

  # GitHub spells the prefix upper-case and the groups lower-case.
  defp normalize_id("GHSA-" <> groups), do: "GHSA-" <> String.downcase(groups)

  defp normalize_id(<<_prefix::binary-size(5), groups::binary>>), do: "GHSA-" <> String.downcase(groups)
end
