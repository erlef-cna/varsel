# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.App do
  @moduledoc """
  The requests Varsel sends to GitHub about the GitHub App's installations.

  The App authenticates with a JSON Web Token that its private key signs.
  The JWT lists the App's installations and mints their installation
  tokens. An installation token lists the repositories of a selective
  installation. A person's own token lists the installations that the
  person reaches and the repositories of each that the person can access.
  `app_id` and `private_key` in `config :varsel, :github`
  configure the App. Without them the App is inert: every request that
  needs the JWT answers `{:error, :not_configured}` and sends nothing.

  `Varsel.GitHub.Installation` and `Varsel.GitHub.UserInstallation` store
  what these requests answer.
  """

  alias Varsel.GitHub.Client

  @jwt_backdate 60
  @jwt_lifetime 600

  @typedoc "An installation of the App, as GitHub describes it."
  @type installation :: %{
          id: pos_integer(),
          account: String.t(),
          kind: :organization | :user,
          repository_selection: :all | :selected,
          suspended_at: DateTime.t() | nil
        }

  @typedoc "A repository that an installation token reaches."
  @type repository :: %{owner: String.t(), repo: String.t()}

  @doc "Whether the App has an id and a private key to act as itself with."
  @spec configured?() :: boolean()
  def configured?, do: match?({:ok, _app_id, _key}, credentials())

  @doc """
  The account whose installation acts for requests about no particular
  repository, or nil when none is configured.
  """
  @spec home_org() :: String.t() | nil
  def home_org do
    case Application.get_env(:varsel, :github, [])[:home_org] do
      account when is_binary(account) and account != "" -> account
      _none -> nil
    end
  end

  @doc """
  The App's URL name on GitHub, as in `https://github.com/apps/<slug>`, or
  nil when none is configured.
  """
  @spec slug() :: String.t() | nil
  def slug do
    case Application.get_env(:varsel, :github, [])[:app_slug] do
      slug when is_binary(slug) and slug != "" -> slug
      _none -> nil
    end
  end

  @doc "Every installation of the App, from all pages of GitHub's answer."
  @spec installations() ::
          {:ok, [installation()]} | {:error, :not_configured | :unauthorized | term()}
  def installations do
    with {:ok, jwt} <- jwt() do
      paginate([auth: {:bearer, jwt}], "/app/installations", fn
        installations when is_list(installations) -> describe_all(installations)
        body -> {:error, {:unexpected_body, body}}
      end)
    end
  end

  @doc """
  The repositories that the installation token `token` reaches, from all
  pages of GitHub's answer.
  """
  @spec installation_repositories(String.t()) ::
          {:ok, [repository()]} | {:error, :unauthorized | term()}
  def installation_repositories(token) when is_binary(token) do
    paginate([auth: {:bearer, token}], "/installation/repositories", &repositories/1)
  end

  defp repositories(%{"repositories" => repositories}) when is_list(repositories),
    do: {:ok, for(%{"name" => repo, "owner" => %{"login" => owner}} <- repositories, do: %{owner: owner, repo: repo})}

  defp repositories(body), do: {:error, {:unexpected_body, body}}

  @doc """
  The App's installations that the user access token `user_token`
  reaches, from all pages of GitHub's answer.
  """
  @spec user_installations(String.t()) ::
          {:ok, [installation()]} | {:error, :unauthorized | term()}
  def user_installations(user_token) when is_binary(user_token) do
    paginate([auth: {:bearer, user_token}], "/user/installations", fn
      %{"installations" => installations} when is_list(installations) ->
        describe_all(installations)

      body ->
        {:error, {:unexpected_body, body}}
    end)
  end

  @doc """
  The repositories of the installation `installation_id` that the user
  access token `user_token` reaches, from all pages of GitHub's answer.
  GitHub lists only the repositories the person can access, so the list
  can be shorter than the installation's own.
  """
  @spec user_installation_repositories(String.t(), pos_integer()) ::
          {:ok, [repository()]} | {:error, :unauthorized | term()}
  def user_installation_repositories(user_token, installation_id)
      when is_binary(user_token) and is_integer(installation_id) do
    paginate(
      [auth: {:bearer, user_token}],
      "/user/installations/#{installation_id}/repositories",
      &repositories/1
    )
  end

  @doc """
  Mints an installation token for the installation `installation_id`.
  GitHub makes it valid for one hour.
  """
  @spec mint(pos_integer()) ::
          {:ok, %{token: String.t(), expires_at: DateTime.t()}} | {:error, term()}
  def mint(installation_id) when is_integer(installation_id) do
    with {:ok, jwt} <- jwt() do
      [auth: {:bearer, jwt}]
      |> Client.api()
      |> Req.post(url: "/app/installations/:id/access_tokens", path_params: [id: installation_id])
      |> minted()
    end
  end

  defp minted({:ok, %Req.Response{status: 201, body: %{"token" => token, "expires_at" => expires_at}}})
       when is_binary(token) do
    with {:ok, expires_at, _offset} <- DateTime.from_iso8601(expires_at) do
      {:ok, %{token: token, expires_at: expires_at}}
    end
  end

  defp minted(other), do: error(other)

  @doc false
  @spec jwt() :: {:ok, String.t()} | {:error, :not_configured}
  def jwt do
    with {:ok, app_id, key} <- credentials() do
      now = System.system_time(:second)
      claims = %{"iss" => app_id, "iat" => now - @jwt_backdate, "exp" => now + @jwt_lifetime}

      {_meta, token} =
        key |> JOSE.JWT.sign(%{"alg" => "RS256"}, claims) |> JOSE.JWS.compact()

      {:ok, token}
    end
  end

  defp paginate(auth, url, items, page \\ 1, found \\ []) do
    auth
    |> Client.api()
    |> Req.get(url: url, params: [per_page: 100, page: page])
    |> case do
      {:ok, %Req.Response{status: 200, body: body} = response} ->
        with {:ok, page_items} <- items.(body) do
          continue(auth, url, items, next_page(response), [page_items | found])
        end

      other ->
        error(other)
    end
  end

  defp continue(_auth, _url, _items, nil, found), do: {:ok, found |> Enum.reverse() |> Enum.concat()}

  defp continue(auth, url, items, next, found), do: paginate(auth, url, items, next, found)

  # GitHub names the next page in a `Link` header. Only its `page` number is
  # taken, so the next request goes to the same path on the same host.
  defp next_page(response) do
    response
    |> Req.Response.get_header("link")
    |> Enum.flat_map(&String.split(&1, ","))
    |> Enum.find_value(fn link ->
      with [_link, target] <- Regex.run(~r/<([^>]+)>\s*;\s*rel="next"/, link),
           %URI{query: query} when is_binary(query) <- URI.parse(target),
           {page, ""} <- query |> URI.decode_query() |> Map.get("page", "") |> Integer.parse() do
        page
      else
        _other -> nil
      end
    end)
  end

  defp describe_all(installations) do
    installations
    |> Enum.reduce_while({:ok, []}, fn body, {:ok, described} ->
      case describe(body) do
        {:ok, installation} -> {:cont, {:ok, [installation | described]}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
    |> case do
      {:ok, described} -> {:ok, Enum.reverse(described)}
      error -> error
    end
  end

  defp describe(%{"id" => id, "account" => %{"login" => login}} = body) when is_integer(id) do
    with {:ok, suspended_at} <- suspended_at(body["suspended_at"]) do
      {:ok,
       %{
         id: id,
         account: login,
         kind: if(body["target_type"] == "User", do: :user, else: :organization),
         repository_selection: if(body["repository_selection"] == "selected", do: :selected, else: :all),
         suspended_at: suspended_at
       }}
    end
  end

  defp describe(body), do: {:error, {:unexpected_body, body}}

  defp suspended_at(nil), do: {:ok, nil}

  defp suspended_at(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, suspended_at, _offset} -> {:ok, suspended_at}
      {:error, reason} -> {:error, {:unexpected_suspended_at, reason}}
    end
  end

  defp error({:ok, %Req.Response{status: 401}}), do: {:error, :unauthorized}

  defp error({:ok, %Req.Response{status: status, body: body}}), do: {:error, {:http, status, body}}

  defp error({:error, exception}), do: {:error, exception}

  defp credentials do
    config = Application.get_env(:varsel, :github, [])

    with app_id when is_binary(app_id) and app_id != "" <- config[:app_id],
         pem when is_binary(pem) and pem != "" <- config[:private_key],
         {:ok, key} <- key(pem) do
      {:ok, app_id, key}
    else
      _missing -> {:error, :not_configured}
    end
  end

  # A deployment passes the PEM through an environment variable, which often
  # carries its newlines as the two characters `\n`.
  defp key(pem) do
    cache_key = {__MODULE__, :erlang.phash2(pem)}

    case :persistent_term.get(cache_key, nil) do
      nil ->
        pem
        |> String.replace("\\n", "\n")
        |> JOSE.JWK.from_pem()
        |> case do
          %JOSE.JWK{} = key ->
            :persistent_term.put(cache_key, key)
            {:ok, key}

          _invalid ->
            :error
        end

      key ->
        {:ok, key}
    end
  end
end
