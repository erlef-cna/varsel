# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Render.Channel do
  @moduledoc """
  Renders `affected[]` entries: one per `Varsel.Cases.PackageChannel` plus
  the implicit git/forge entry every package with a `repo_url` gets.

  Channels are purl-shaped (type + namespace/name + qualifiers); the purl
  type fixes the entry constants (collectionURL, versionType semantics live
  in `Varsel.Cases.Derivation`). The two channel escape hatches
  (`versions_override`, `entry_override`) apply last. The git entry derives
  everything from the repository URL — a purl only for forges with a
  registered purl type (github/gitlab/bitbucket); other forges keep
  vendor/product/repo/packageName without inventing one.
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

  @doc """
  The implicit git/forge entry for a package, or nil without a `repo_url`.
  """
  @spec render_git(AffectedPackage.t(), map() | nil) :: map() | nil
  def render_git(%{repo_url: nil}, _git_derivation), do: nil

  def render_git(package, git_derivation) do
    package
    |> base_entry()
    |> Map.merge(git_constants(package))
    |> put_versions((git_derivation || %{})["versions"] || [])
  end

  @doc "The composed packageURL of a channel (nil for hosted channels and unnamed forges)."
  @spec purl_string(AffectedPackage.t(), PackageChannel.t()) :: String.t() | nil
  def purl_string(_package, %{purl_type: :hosted}), do: nil
  def purl_string(_package, %{name: nil}), do: nil

  def purl_string(package, channel) do
    Purl.to_string(
      struct!(Purl,
        type: to_string(channel.purl_type),
        namespace: split_namespace(channel.namespace),
        name: channel.name,
        qualifiers: qualifiers(package, channel)
      )
    )
  end

  ## -------------------------------------------------------- entry assembly

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

  defp channel_constants(_package, %{purl_type: :hosted}) do
    # Hosted services carry no package identity — just vendor/product/versions
    # (see the hex.pm entry in CVE-2026-21618).
    %{}
  end

  defp channel_constants(package, channel) do
    %{"cpes" => [cpe(package)]}
    |> put_present("packageName", package_name(package, channel))
    |> put_present("packageURL", purl_string(package, channel))
    |> put_present("collectionURL", collection_url(package, channel))
    |> put_repo(channel.purl_type, package)
  end

  # The published packageName per ecosystem: oci includes the registry path
  # ("gleam-lang/gleam"), namespaced ecosystems join namespace/name, sid and
  # the rest use the bare name.
  defp package_name(_package, %{purl_type: :oci} = channel) do
    case channel |> repository_url() |> String.split("/", parts: 2) do
      [_host, path] -> "#{path}/#{channel.name}"
      [_host] -> channel.name
    end
  end

  defp package_name(_package, %{purl_type: :sid} = channel), do: channel.name

  defp package_name(_package, channel) do
    case channel.namespace do
      nil -> channel.name
      namespace -> "#{namespace}/#{channel.name}"
    end
  end

  defp collection_url(_package, %{purl_type: :hex}), do: "https://repo.hex.pm"
  defp collection_url(_package, %{purl_type: :npm}), do: "https://registry.npmjs.org"

  defp collection_url(_package, %{purl_type: :oci} = channel) do
    [host | _path] = channel |> repository_url() |> String.split("/", parts: 2)
    "https://#{host}"
  end

  defp collection_url(_package, _channel), do: nil

  defp repository_url(channel), do: channel.qualifiers["repository_url"] || "ghcr.io"

  # Registry entries of repo-backed packages carry the repo too (hex/otp/npm,
  # matching the published records); oci/sid entries do not.
  defp put_repo(constants, purl_type, %{repo_url: repo_url})
       when purl_type in [:hex, :otp, :npm] and is_binary(repo_url) do
    Map.put(constants, "repo", repo_url)
  end

  defp put_repo(constants, _purl_type, _package), do: constants

  defp qualifiers(package, channel) do
    auto =
      case {channel.purl_type, package.repo_url} do
        {:otp, repo_url} when is_binary(repo_url) ->
          %{"repository_url" => repo_url, "vcs_url" => "git #{repo_url}.git"}

        _other ->
          %{}
      end

    Map.merge(auto, channel.qualifiers || %{})
  end

  defp split_namespace(nil), do: []
  defp split_namespace(namespace), do: String.split(namespace, "/", trim: true)

  defp put_versions(entry, []), do: entry
  defp put_versions(entry, versions), do: Map.put(entry, "versions", versions)

  defp put_non_empty(entry, _key, []), do: entry
  defp put_non_empty(entry, key, value), do: Map.put(entry, key, value)

  defp put_present(entry, _key, nil), do: entry
  defp put_present(entry, key, value), do: Map.put(entry, key, value)

  ## ------------------------------------------------------------------ forge

  @forge_purl_types %{
    "github.com" => "github",
    "gitlab.com" => "gitlab",
    "bitbucket.org" => "bitbucket"
  }

  defp git_constants(package) do
    %URI{host: host, path: repo_path} = URI.parse(package.repo_url)
    path = forge_path(repo_path)

    %{"cpes" => [cpe(package)], "repo" => package.repo_url}
    |> put_present("collectionURL", host && "https://#{host}")
    |> put_present("packageName", path)
    |> put_present("packageURL", forge_purl(Map.get(@forge_purl_types, host || ""), path))
  end

  # "/owner/repo.git/" -> "owner/repo"
  defp forge_path(nil), do: nil

  defp forge_path(path) do
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

  ## -------------------------------------------------------------------- cpe

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
end
