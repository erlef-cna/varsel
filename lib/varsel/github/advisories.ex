# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Advisories do
  @moduledoc """
  GitHub security advisories over the REST API: reading a repository's own
  advisory or the global database entry, updating one, reporting one
  privately, and the forms a GHSA is pasted in.

  A read runs as the acting user when their token is given. That is what lets
  GitHub decide whether a draft is theirs to see: a draft they may not see
  answers 404, the same as an advisory that does not exist. Without a token
  only published advisories on public repositories answer. Writes always
  carry the acting user's token: GitHub attributes them to that person and
  decides whether they may. A token GitHub no longer accepts answers
  `{:error, :unauthorized}`.
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
  GitHub's update request, as the user whose token is given. Answers the
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
  Opens a draft advisory on `owner/repo`, as the user whose token is given,
  who has to administer the repository. Answers the draft.
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

  defp request(token, request_opts) do
    token
    |> req()
    |> Req.request(Keyword.put_new(request_opts, :method, :get))
    |> case do
      {:ok, %Req.Response{status: status, body: %{} = body}} when status in [200, 201] ->
        {:ok, body}

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
