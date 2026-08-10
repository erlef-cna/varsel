# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.Preview.Channel do
  @moduledoc """
  Renders `affected[]` entries — one per `Varsel.Cases.PackageChannel`,
  including the source repository's own channel, which is a stored channel like
  any other rather than a second rendering path.

  A `:package` channel is purl-shaped (type + namespace/name + qualifiers) and
  takes its entry constants from `Varsel.Cases.PackageChannel.PurlType`; a
  `:service` channel has no package identity, so it publishes vendor/product
  and its dated versions alone. The two channel escape hatches
  (`versions_override`, `entry_override`) apply last.
  """

  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case.Calculations.Preview.MergePatch
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.PackageChannel.Calculations.Purl, as: PurlCalculation
  alias Varsel.Cases.PackageChannel.PurlType

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
      |> put_program_info(program_files(package, channel))
      |> Map.merge(channel_constants(package, channel))
      |> put_versions(versions)

    {entry, entry_override_applied} =
      case channel.entry_override do
        nil -> {entry, []}
        override -> {MergePatch.apply(entry, override), ["entry_override"]}
      end

    {entry, version_override_applied ++ entry_override_applied}
  end

  @doc "The composed packageURL of a channel (nil for service channels)."
  @spec purl_string(AffectedPackage.t(), PackageChannel.t()) :: String.t() | nil
  def purl_string(_package, channel), do: PurlCalculation.compose(channel)

  ## -------------------------------------------------------- entry assembly

  # defaultStatus is always "unaffected": derivation labels every release, so
  # affected/unknown eras are explicit versions[] ranges and everything else
  # is genuinely unaffected.
  defp base_entry(package) do
    put_non_empty(
      %{
        "defaultStatus" => "unaffected",
        "vendor" => package.vendor,
        "product" => package.product
      },
      "platforms",
      package.platforms
    )
  end

  # The program files an entry covers, as {file, rendered_path} pairs. A
  # channel with a subpath distributes only that directory: files under it
  # apply, paths relative to it (the per-application view of a
  # multi-application repository, see CVE-2026-48858's inets/ftp entries).
  # Without a subpath every file applies under its full repository path.
  defp program_files(package, %{subpath: subpath}) when is_binary(subpath) do
    prefix = String.trim(subpath, "/") <> "/"

    for file <- package.program_files, String.starts_with?(file.path, prefix) do
      {file, String.replace_prefix(file.path, prefix, "")}
    end
  end

  defp program_files(package, _channel), do: Enum.map(package.program_files, &{&1, &1.path})

  # Modules and routines follow the files that contribute them.
  defp put_program_info(entry, files_with_paths) do
    files = Enum.map(files_with_paths, &elem(&1, 0))

    entry
    |> put_non_empty("modules", files |> Enum.flat_map(& &1.modules) |> Enum.uniq())
    |> put_non_empty("programFiles", Enum.map(files_with_paths, &elem(&1, 1)))
    |> put_non_empty(
      "programRoutines",
      files |> Enum.flat_map(& &1.routines) |> Enum.uniq() |> Enum.map(&%{"name" => &1})
    )
  end

  # A service carries no package identity — just vendor/product/versions plus
  # the domain it answers on (see the hex.pm entry in CVE-2026-21618).
  defp channel_constants(package, %{kind: :service} = channel) do
    %{"cpes" => [cpe(package)]}
    |> put_present("collectionURL", service_url(channel))
    |> put_present("packageName", channel.domain)
  end

  defp channel_constants(package, channel) do
    %{"cpes" => [cpe(package)]}
    |> put_present("packageName", package_name(channel))
    |> put_present("packageURL", purl_string(package, channel))
    |> put_present("collectionURL", collection_url(package, channel))
    |> put_repo(channel, package)
  end

  defp service_url(%{domain: nil}), do: nil
  defp service_url(%{domain: domain}), do: "https://#{domain}"

  # The published packageName per ecosystem: oci includes the registry path
  # ("gleam-lang/gleam"), namespaced ecosystems join namespace/name, and
  # everything else publishes the bare name.
  defp package_name(%{purl_type: "oci"} = channel) do
    case channel |> oci_repository_url() |> String.split("/", parts: 2) do
      [_host, path] -> "#{path}/#{channel.name}"
      [_host] -> channel.name
    end
  end

  defp package_name(channel) do
    if PurlType.namespaced?(channel.purl_type) and channel.namespace do
      "#{channel.namespace}/#{channel.name}"
    else
      channel.name
    end
  end

  # An OCI image's registry is per-channel (its repository_url qualifier), so
  # unlike every other type its collectionURL cannot come from the type alone.
  defp collection_url(_package, %{purl_type: "oci"} = channel) do
    [host | _path] = channel |> oci_repository_url() |> String.split("/", parts: 2)
    "https://#{host}"
  end

  defp collection_url(package, channel) do
    PurlType.collection_url(channel.purl_type) || forge_url(package, channel)
  end

  # No purl type names a forge's URL, so a repository channel takes it from the
  # repository itself.
  defp forge_url(%{repo_url: repo_url}, channel) when is_binary(repo_url) do
    if PurlType.default_version_type(channel.purl_type) == :git do
      case URI.parse(repo_url) do
        %URI{host: host} when is_binary(host) -> "https://#{host}"
        _no_host -> nil
      end
    end
  end

  defp forge_url(_package, _channel), do: nil

  defp oci_repository_url(channel), do: channel.qualifiers["repository_url"] || "ghcr.io"

  # Repo-backed entries name the repository (matching the published records);
  # entries of packages published independently of it do not.
  defp put_repo(constants, channel, %{repo_url: repo_url}) when is_binary(repo_url) do
    if PurlType.repo_backed?(channel.purl_type) do
      Map.put(constants, "repo", repo_url)
    else
      constants
    end
  end

  defp put_repo(constants, _channel, _package), do: constants

  defp put_versions(entry, []), do: entry
  defp put_versions(entry, versions), do: Map.put(entry, "versions", versions)

  defp put_non_empty(entry, _key, []), do: entry
  defp put_non_empty(entry, key, value), do: Map.put(entry, key, value)

  defp put_present(entry, _key, nil), do: entry
  defp put_present(entry, key, value), do: Map.put(entry, key, value)

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
