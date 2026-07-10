# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.HexPm do
  @moduledoc """
  Thin client for checking package existence on hex.pm via `hex_core`.

  Extra `hex_core` configuration (e.g. a stub HTTP adapter in tests) can be
  merged in via

      config :cve_management, :hex_core, %{http_adapter: {MyAdapter, %{}}}
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

  @doc """
  Extracts the package names of all `pkg:hex/...` package URLs in a CVE
  record's affected entries.

  Namespaced purls (`pkg:hex/acme/foo`, private organization packages) are
  skipped — their existence cannot be verified against the public repository.
  Unparsable package URLs are skipped as well; the schema/lint validators are
  responsible for flagging those.
  """
  @spec hex_package_names(map()) :: [String.t()]
  def hex_package_names(cve_json) when is_map(cve_json) do
    cve_json
    |> get_in(["containers", "cna", "affected"])
    |> List.wrap()
    |> Enum.flat_map(fn affected ->
      with %{"packageURL" => purl_string} <- affected,
           {:ok, %Purl{type: "hex", namespace: [], name: name}} <- Purl.new(purl_string) do
        [name]
      else
        _ -> []
      end
    end)
    |> Enum.uniq()
  end

  defp config do
    Map.merge(
      :hex_core.default_config(),
      Application.get_env(:cve_management, :hex_core, %{})
    )
  end
end
