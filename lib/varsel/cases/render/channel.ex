# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Render.Channel do
  @moduledoc """
  Renders one `Varsel.Cases.PackageChannel` into its `affected[]` entry.

  The channel type fixes the entry constants (collectionURL, packageURL purl
  scheme, versionType — invariants across every published EEF record); the
  version data comes from the package's derivation result; the two channel
  escape hatches (`versions_override`, `entry_override`) apply last.
  """

  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.Render.MergePatch

  @doc """
  The rendered `affected[]` entry for a channel. Returns
  `{entry, overrides_applied}` where overrides_applied names the escape
  hatches that fired.
  """
  @spec render(AffectedPackage.t(), PackageChannel.t(), map()) :: {map(), [String.t()]}
  def render(package, channel, channel_derivation) do
    {versions, version_override_applied} =
      case channel.versions_override do
        nil -> {channel_derivation["versions"] || [], []}
        override -> {override, ["versions_override"]}
      end

    entry =
      package
      |> base_entry()
      |> Map.merge(channel_constants(package, channel))
      |> put_versions(versions)

    {entry, entry_override_applied} =
      case channel.entry_override do
        nil -> {entry, []}
        override -> {MergePatch.apply(entry, override), ["entry_override"]}
      end

    {entry, version_override_applied ++ entry_override_applied}
  end

  defp base_entry(package) do
    %{
      "defaultStatus" => to_string(package.default_status),
      "vendor" => package.vendor,
      "product" => package.product
    }
    |> put_non_empty("modules", package.modules)
    |> put_non_empty("programFiles", package.program_files)
    |> put_non_empty("programRoutines", Enum.map(package.program_routines, &%{"name" => &1}))
    |> put_non_empty("platforms", package.platforms)
  end

  defp put_versions(entry, []), do: entry
  defp put_versions(entry, versions), do: Map.put(entry, "versions", versions)

  defp put_non_empty(entry, _key, []), do: entry
  defp put_non_empty(entry, key, value), do: Map.put(entry, key, value)

  defp channel_constants(package, %{channel_type: :git} = channel) do
    put_repo(
      %{
        "collectionURL" => "https://github.com",
        "packageName" => channel.package_name,
        "packageURL" => github_purl(channel.package_name),
        "cpes" => [cpe(package)]
      },
      package
    )
  end

  defp channel_constants(package, %{channel_type: :hex} = channel) do
    put_repo(
      %{
        "collectionURL" => "https://repo.hex.pm",
        "packageName" => channel.package_name,
        "packageURL" => purl("hex", channel.package_name),
        "cpes" => [cpe(package)]
      },
      package
    )
  end

  defp channel_constants(package, %{channel_type: :otp} = channel) do
    put_repo(
      %{
        "packageName" => channel.package_name,
        "packageURL" => otp_purl(channel.package_name, package.repo_url),
        "cpes" => [cpe(package)]
      },
      package
    )
  end

  defp channel_constants(package, %{channel_type: :npm} = channel) do
    put_repo(
      %{
        "collectionURL" => channel.registry_url || "https://registry.npmjs.org",
        "packageName" => channel.package_name,
        "packageURL" => purl("npm", channel.package_name),
        "cpes" => [cpe(package)]
      },
      package
    )
  end

  defp channel_constants(package, %{channel_type: :oci} = channel) do
    registry = channel.registry_url || "ghcr.io"
    [host | _] = String.split(registry, "/", parts: 2)

    %{
      "collectionURL" => "https://#{host}",
      "packageName" => channel.package_name,
      "packageURL" => oci_purl(channel.package_name, registry),
      "cpes" => [cpe(package)]
    }
  end

  defp channel_constants(package, %{channel_type: :sid} = channel) do
    %{
      "packageName" => channel.package_name |> String.split("/") |> List.last(),
      "packageURL" => sid_purl(channel.package_name),
      "cpes" => [cpe(package)]
    }
  end

  # Hosted services carry no package identity — just vendor/product/versions
  # (see the hex.pm entry in CVE-2026-21618).
  defp channel_constants(_package, %{channel_type: :hosted}), do: %{}

  defp put_repo(constants, %{repo_url: nil}), do: constants
  defp put_repo(constants, %{repo_url: repo_url}), do: Map.put(constants, "repo", repo_url)

  @doc "The package's CPE 2.3 string, derived from vendor/product when not set explicitly."
  @spec cpe(AffectedPackage.t()) :: String.t()
  def cpe(%{cpe: cpe}) when not is_nil(cpe), do: cpe

  def cpe(package) do
    "cpe:2.3:a:#{cpe_component(package.vendor)}:#{cpe_component(package.product)}:*:*:*:*:*:*:*:*"
  end

  # CPE 2.3 formatted-string escaping for the vendor/product components:
  # anything outside the unquoted alphabet gets a backslash (erlang/otp ->
  # erlang\/otp, as published in the real records).
  defp cpe_component(value) do
    value
    |> String.downcase()
    |> String.replace(" ", "_")
    |> String.replace(~r/[^a-z0-9._-]/, fn char -> "\\" <> char end)
  end

  defp github_purl(package_name) do
    case String.split(package_name || "", "/") do
      [owner, name] ->
        Purl.to_string(struct!(Purl, type: "github", namespace: [owner], name: name))

      _other ->
        Purl.to_string(struct!(Purl, type: "github", name: package_name || ""))
    end
  end

  defp purl(type, name), do: Purl.to_string(struct!(Purl, type: type, name: name))

  defp otp_purl(app, repo_url) do
    qualifiers =
      if repo_url do
        %{"repository_url" => repo_url, "vcs_url" => "git #{repo_url}.git"}
      else
        %{}
      end

    Purl.to_string(struct!(Purl, type: "otp", name: app, qualifiers: qualifiers))
  end

  defp oci_purl(package_name, registry) do
    name = package_name |> String.split("/") |> List.last()

    Purl.to_string(struct!(Purl, type: "oci", name: name, qualifiers: %{"repository_url" => registry}))
  end

  defp sid_purl(package_name) do
    case String.split(package_name, "/") do
      [name] ->
        Purl.to_string(struct!(Purl, type: "sid", name: name))

      parts ->
        Purl.to_string(struct!(Purl, type: "sid", namespace: Enum.drop(parts, -1), name: List.last(parts)))
    end
  end
end
