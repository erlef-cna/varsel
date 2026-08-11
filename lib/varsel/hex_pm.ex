# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.HexPm do
  @moduledoc """
  Thin client for hex.pm, via `hex_core`.

  Extra `hex_core` configuration (a stub HTTP adapter in tests) is merged in
  via `config :varsel, :hex_core, %{http_adapter: {MyAdapter, %{}}}`.
  """

  @doc """
  Checks whether a package exists on hex.pm.

  Returns `{:ok, true | false}` or `{:error, reason}` on transport errors.
  """
  @spec package_exists?(String.t()) :: {:ok, boolean()} | {:error, String.t()}
  def package_exists?(name) when is_binary(name) do
    case :hex_api_package.get(config(), name) do
      {:ok, {200, _headers, _body}} -> {:ok, true}
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
    case :hex_api_package.get(config(), name) do
      {:ok, {200, _headers, body}} ->
        {:ok, body |> Map.get("releases", []) |> Enum.map(& &1["version"])}

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

  defp config do
    Map.merge(:hex_core.default_config(), Application.get_env(:varsel, :hex_core, %{}))
  end
end
