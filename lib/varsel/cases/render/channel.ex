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

  # Git channels are forge-aware: host and default path come from the
  # package's repo_url; a purl is only emitted for forges with a registered
  # purl type (github/gitlab/bitbucket) — other forges keep vendor/product/
  # repo/packageName without a packageURL rather than inventing one.
  defp channel_constants(package, %{channel_type: :git} = channel) do
    constants = put_repo(%{"cpes" => [cpe(package)]}, package)

    case forge(package.repo_url, channel.package_name) do
      nil ->
        constants

      %{host: host, path: path, purl_type: purl_type} ->
        constants
        |> Map.put("collectionURL", "https://#{host}")
        |> put_present("packageName", path)
        |> put_present("packageURL", forge_purl(purl_type, path))
    end
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

  @forge_purl_types %{
    "github.com" => "github",
    "gitlab.com" => "gitlab",
    "bitbucket.org" => "bitbucket"
  }

  # Resolves the forge host, the in-forge path ("owner/repo"), and the purl
  # type (nil for forges without one). The path prefers the channel's
  # package_name — normalized, so a pasted clone URL still works — and falls
  # back to the repo_url's own path.
  defp forge(repo_url, package_name) do
    case URI.parse(repo_url || "") do
      %URI{host: host, path: repo_path} when is_binary(host) ->
        %{
          host: host,
          path: forge_path(package_name) || forge_path(repo_path),
          purl_type: Map.get(@forge_purl_types, host)
        }

      _no_repo ->
        # No usable repo_url: a plain "owner/repo" name still renders, but
        # without a host there is no collectionURL or purl to derive.
        nil
    end
  end

  @doc """
  Normalizes a forge path: a pasted clone URL, a leading/trailing-slashed
  path, or a bare "owner/repo" all become "owner/repo" (nil when nothing
  usable remains).

      "https://github.com/owner/repo.git" | "/owner/repo/" | "owner/repo" -> "owner/repo"
  """
  @spec forge_path(String.t() | nil) :: String.t() | nil
  def forge_path(nil), do: nil

  def forge_path(value) do
    path = if value =~ "://", do: URI.parse(value).path || "", else: value

    case path |> String.trim("/") |> String.replace_suffix(".git", "") do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp forge_purl(nil, _path), do: nil
  defp forge_purl(_type, nil), do: nil

  defp forge_purl(type, path) do
    case String.split(path, "/") do
      [name] ->
        Purl.to_string(struct!(Purl, type: type, name: name))

      parts ->
        # Multi-segment namespaces cover gitlab subgroups (owner/group/repo).
        Purl.to_string(struct!(Purl, type: type, namespace: Enum.drop(parts, -1), name: List.last(parts)))
    end
  end

  defp put_present(constants, _key, nil), do: constants
  defp put_present(constants, key, value), do: Map.put(constants, key, value)

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
