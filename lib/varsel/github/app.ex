# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.App do
  @moduledoc """
  The requests Varsel sends to GitHub as the GitHub App itself.

  The App authenticates with a JSON Web Token that its private key signs.
  The JWT finds the App's installations and mints their installation tokens.
  `app_id` and `private_key` in `config :varsel, :github` configure the App.
  Without them the App is inert: every lookup answers `:not_installed` and
  every mint answers `{:error, :not_configured}`.

  `Varsel.GitHub.Installation` and `Varsel.GitHub.UserInstallation` cache
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
          repository_selection: :all | :selected
        }

  @type lookup :: {:ok, installation()} | :not_installed | {:error, term()}

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

  @doc "The installation of the App on the repository `owner/repo`."
  @spec repository_installation(String.t(), String.t()) :: lookup()
  def repository_installation(owner, repo) when is_binary(owner) and is_binary(repo) do
    installation("/repos/:owner/:repo/installation", owner: owner, repo: repo)
  end

  @doc "The installation of the App on the organization `account`."
  @spec org_installation(String.t()) :: lookup()
  def org_installation(account) when is_binary(account) do
    installation("/orgs/:org/installation", org: account)
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

  @doc """
  The ids of the App's installations that the user access token
  `user_token` reaches.
  """
  @spec user_installations(String.t()) ::
          {:ok, [pos_integer()]} | {:error, :unauthorized | term()}
  def user_installations(user_token) when is_binary(user_token) do
    [auth: {:bearer, user_token}]
    |> Client.api()
    |> Req.get(url: "/user/installations", params: [per_page: 100])
    |> case do
      {:ok, %Req.Response{status: 200, body: %{"installations" => installations}}}
      when is_list(installations) ->
        {:ok, for(%{"id" => id} <- installations, is_integer(id), do: id)}

      other ->
        error(other)
    end
  end

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

  defp installation(url, path_params) do
    case jwt() do
      {:ok, jwt} ->
        [auth: {:bearer, jwt}]
        |> Client.api()
        |> Req.get(url: url, path_params: path_params)
        |> case do
          {:ok, %Req.Response{status: 200, body: %{} = body}} -> describe(body)
          {:ok, %Req.Response{status: 404}} -> :not_installed
          other -> error(other)
        end

      {:error, :not_configured} ->
        :not_installed
    end
  end

  defp describe(%{"id" => id, "account" => %{"login" => login}} = body) when is_integer(id) do
    {:ok,
     %{
       id: id,
       account: login,
       kind: if(body["target_type"] == "User", do: :user, else: :organization),
       repository_selection: if(body["repository_selection"] == "selected", do: :selected, else: :all)
     }}
  end

  defp describe(body), do: {:error, {:unexpected_body, body}}

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
