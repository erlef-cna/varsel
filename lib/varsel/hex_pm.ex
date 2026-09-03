# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.HexPm do
  @moduledoc """
  Thin client for hex.pm.

  Talks to the same instance sign-in does: hex.pm is self-hostable, and asking
  one host who a user is while asking another whether that user exists would
  answer about two different people. Users are looked up on that instance's
  API; packages are read from its signed registry, which is unauthenticated
  and not rate limited. The registry host and signing key follow the
  instance: hex.pm's are hex_core's defaults, staging's and a local hexpm
  checkout's are known here, and any other instance is expected at
  `<base_url>/repo` with its key supplied through the `:hex_core` config.

  Extra `hex_core` configuration (a stub HTTP adapter in tests) is merged in
  via `config :varsel, :hex_core, %{http_adapter: {MyAdapter, %{}}}`. The
  contact lookup goes through `Req` instead, since hex.pm serves it as plain
  JSON behind a service token. Its request options (a `Req.Test` plug in
  tests) come from `config :varsel, :hex_api`.
  """

  alias Varsel.HexPm.ServiceToken

  @typedoc """
  Who a hex.pm account belongs to. `email` is `nil` when the account has no
  verified address.
  """
  @type contact :: %{username: String.t(), name: String.t(), email: String.t() | nil}

  @staging_repo_public_key """
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA56Ac/wvs6VjHOC48BNFO
  WPrxrogxKEvD3DeYWEbJaPvRLtlan9mw5fIjlA5zHsmwyWfItQmOWxayWD1rHPjP
  FW7WHs7h3ceSI6g3sIgsUp5Tw1x1gedPm5n+pkPovfhLGADpi+WmkHLLIIAQUrmP
  7mlRgnfkdizGuqTbG7qmRoGmAXqEiZMNBsm8TtfIsBPUjnZcHizwMdytSkwqfQsP
  K0kbtVsGPpdRKdkf+uMfIG+mJPKrIc0YZdhfAiD2kwmzoij2K01l7TrI/U5g1Yb7
  6O9nw0Y47KB6o9Hzwfkk/KUVPn0hrcGmkbAOKe03PxYTlyrockvEP9Hu6ncGvyby
  FQIDAQAB
  -----END PUBLIC KEY-----
  """

  # hexpm's dev signing key (test/fixtures/private.pem in its repository).
  @dev_repo_public_key """
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA70iFalPXSDJX0ZqQNYw2
  yPyMWmpV4ssLwuGm4l3TjS50UgKYnyL2j7m0mmO7DhLNqRKn8IsIJoHeeuFhf5cv
  W162mp2Kn2e9LXRobafYIM3hxzB8LZqeQjxPR6xsDkY5HgQsxtTkbNRq/8ODAjx6
  XsZgFRSkjgD+nWO0D4i67+8lWSyGBaXAvyYQVRimkvm400PYD4RT2dk9lSrBjhAv
  sZ+buCX/F8XuK2sOdhoFC7PXz4kO2q41IF1LjVfKz6WdXH91jUCUG80TAzK35lRT
  GRes/NOIV/aYwt6fc3BjgzOg/X8ucFwuWi5Tn5lU+eFYHcv1Qyxxx9yi03pZ7hH4
  iwIDAQAB
  -----END PUBLIC KEY-----
  """

  @doc """
  Checks whether a package exists on hex.pm.

  Returns `{:ok, true | false}` or `{:error, reason}` on transport errors.
  """
  @spec package_exists?(String.t()) :: {:ok, boolean()} | {:error, String.t()}
  def package_exists?(name) when is_binary(name) do
    case :hex_repo.get_package(config(), name) do
      {:ok, {200, _headers, _package}} -> {:ok, true}
      {:ok, {404, _headers, _body}} -> {:ok, false}
      {:ok, {status, _headers, _body}} -> {:error, "hex.pm returned #{status} for #{name}"}
      {:error, reason} -> {:error, "hex.pm request for #{name} failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Lists all released versions of a package on hex.pm.

  Returns `{:ok, versions}` or `{:error, reason}` when the package does not
  exist or the request fails.
  """
  @spec package_versions(String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def package_versions(name) when is_binary(name) do
    case :hex_repo.get_package(config(), name) do
      {:ok, {200, _headers, %{releases: releases}}} ->
        {:ok, Enum.map(releases, & &1.version)}

      {:ok, {status, _headers, _body}} ->
        {:error, "hex.pm returned #{status} for #{name}"}

      {:error, reason} ->
        {:error, "hex.pm request for #{name} failed: #{inspect(reason)}"}
    end
  end

  @doc "Whether a hex.pm account with this username exists, and its canonical spelling."
  @spec user(String.t()) :: {:ok, String.t()} | :not_found
  def user(username) when is_binary(username) do
    case :hex_api_user.get(config(), username) do
      {:ok, {200, _headers, %{"username" => canonical}}} -> {:ok, canonical}
      {:ok, {404, _headers, _body}} -> :not_found
    end
  end

  @doc """
  Asks hex.pm who an account belongs to.

  `name` is a username or an email address. hex.pm answers about a person's
  own account only. An organization, service or deactivated account is
  `:not_found`, and so is a name it does not know.
  """
  @spec contact(String.t()) :: {:ok, contact()} | :not_found | {:error, term()}
  def contact(name) when is_binary(name) do
    audience = base_url()
    path = "/api/users/#{URI.encode(name, &URI.char_unreserved?/1)}/contact"

    with {:ok, token} <- ServiceToken.sign(audience),
         {:ok, response} <- Req.get(contact_req(audience), url: path, auth: {:bearer, token}) do
      case response do
        %Req.Response{status: 200, body: %{"username" => username, "name" => display_name} = body} ->
          {:ok, %{username: username, name: display_name, email: body["email"]}}

        %Req.Response{status: 404} ->
          :not_found

        %Req.Response{} = response ->
          {:error, response}
      end
    end
  end

  defp contact_req(base_url) do
    Req.new(
      [base_url: base_url, retry: false, headers: [{"accept", "application/json"}]] ++
        Application.get_env(:varsel, :hex_api, [])
    )
  end

  defp config do
    :hex_core.default_config()
    |> Map.merge(instance_config())
    |> Map.merge(Application.get_env(:varsel, :hex_core, %{}))
  end

  # The OAuth strategy's `base_url` is the site root and it appends `/api`,
  # which is also how hex.pm's own default is shaped.
  defp instance_config do
    base_url = base_url()
    Map.put(repo_config(base_url), :api_url, base_url <> "/api")
  end

  defp base_url do
    :varsel
    |> Application.get_env(:hex, [])
    |> Keyword.get(:base_url, "https://hex.pm")
    |> String.trim_trailing("/")
  end

  defp repo_config("https://hex.pm"), do: %{}

  defp repo_config("https://staging.hex.pm"),
    do: %{repo_url: "https://repo.staging.hex.pm", repo_public_key: @staging_repo_public_key}

  defp repo_config("http://localhost:" <> _port = base_url),
    do: %{repo_url: base_url <> "/repo", repo_public_key: @dev_repo_public_key}

  defp repo_config(base_url), do: %{repo_url: base_url <> "/repo"}
end
