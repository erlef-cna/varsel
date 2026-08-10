# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.PurlType do
  @moduledoc """
  What we know about a Package URL type — an *open* vocabulary, not an enum.

  Any purl type may be authored. This module supplies the conventions of the
  ones we know (their registry URL, how they version, whether they carry a
  namespace, which forge host they belong to) and degrades to sane neutral
  answers for the ones we do not, so publishing an advisory for an ecosystem
  we have never seen needs a row, not a code change.

  Known-type knowledge is deliberately thin: it only covers what the rendered
  `affected[]` entry needs (`collectionURL`, `versionType`) plus the forge
  mapping the repository channel is derived through.

  Types absent from these tables still work — that is the point of an open
  vocabulary. `sid` (software without a registry, purl-spec decision 001) is
  one: it needs no entry, since it takes the neutral defaults. The spec has
  since renamed it, and we keep publishing `sid` until the final type lands —
  a change of stored data, not of code.
  """

  alias Varsel.Cases.PackageChannel.VersionType

  # Registry a type's packages are fetched from — rendered as collectionURL.
  # Only types with a single canonical registry appear: pkg:oci's registry is
  # per-channel (its repository_url qualifier), so it is resolved there.
  @collection_urls %{
    "hex" => "https://repo.hex.pm",
    "npm" => "https://registry.npmjs.org",
    "cargo" => "https://crates.io",
    "gem" => "https://rubygems.org",
    "golang" => "https://proxy.golang.org",
    "maven" => "https://repo.maven.apache.org/maven2",
    "nuget" => "https://www.nuget.org",
    "pypi" => "https://pypi.org",
    "composer" => "https://packagist.org"
  }

  # How a type versions itself, when the channel does not say. Everything
  # absent here is semver: it is what registries overwhelmingly use, and a
  # channel that disagrees sets version_type explicitly.
  @version_types %{
    "otp" => :otp,
    "oci" => :other,
    "github" => :git,
    "bitbucket" => :git,
    "generic" => :git
  }

  # Types whose purl carries a namespace that is part of the published package
  # name ("@scope/pkg", "owner/repo"). Used to spell packageName the way each
  # ecosystem does.
  @namespaced ~w(npm github bitbucket maven golang composer)

  @doc "The registry URL packages of this type are fetched from, or nil."
  @spec collection_url(String.t() | nil) :: String.t() | nil
  def collection_url(nil), do: nil
  def collection_url(purl_type), do: Map.get(@collection_urls, purl_type)

  @doc """
  The `versionType` this purl type uses when the channel does not name one.
  Unknown types version in semver.
  """
  @spec default_version_type(String.t() | nil) :: VersionType.t()
  def default_version_type(nil), do: :semver
  def default_version_type(purl_type), do: Map.get(@version_types, purl_type, :semver)

  @doc """
  Whether this type's namespace is part of the package's published name, so
  `packageName` joins it as `<namespace>/<name>`.
  """
  @spec namespaced?(String.t() | nil) :: boolean()
  def namespaced?(purl_type), do: purl_type in @namespaced

  @doc """
  The channel identity of a source repository: the purl parts describing the
  repo at `repo_url`, as `{purl_type, namespace, name, qualifiers}`.

  Which forges have a registered purl type is `purl`'s knowledge rather than a
  host table of ours — `github` and `bitbucket` do, `gitlab` notably does not.
  A repository `purl` cannot type is still a channel: `pkg:generic` carrying
  the repository in its `vcs_url` qualifier, which is what the purl spec says
  to do rather than inventing a type for the forge.

  The version is dropped either way: `Purl.from_resource_uri/1` pins `@HEAD`,
  but a channel names no single version — its bounds come from the case's
  boundary facts.
  """
  @spec for_repository(String.t()) :: {String.t(), String.t() | nil, String.t(), map()}
  def for_repository(repo_url) do
    case Purl.from_resource_uri(repo_url) do
      {:ok, %Purl{type: type, namespace: namespace, name: name}} ->
        {type, namespace_string(namespace), name, %{}}

      :error ->
        {"generic", nil, generic_repo_name(repo_url), %{"vcs_url" => "git+#{repo_url}"}}
    end
  end

  defp namespace_string([]), do: nil
  defp namespace_string(namespace), do: Enum.join(namespace, "/")

  # An untyped forge still needs a name: the last path segment is the repository
  # ("repo" of git.example.com/team/repo.git), the host when there is no path.
  defp generic_repo_name(repo_url) do
    %URI{host: host, path: path} = URI.parse(repo_url)

    (path || "")
    |> String.replace_suffix(".git", "")
    |> String.split("/", trim: true)
    |> List.last()
    |> Kernel.||(host)
  end

  # Types built straight from a repository rather than published to a registry.
  # `otp` is one: OTP applications ship with the OTP release, so their entries
  # name the repo the way the published records do.
  @repo_backed ~w(otp)

  @doc """
  Whether the entry should repeat the package's `repo` field. Registry entries
  of repo-backed packages carry it (matching the published records); the
  repository channel carries it because it *is* the repository.
  """
  @spec repo_backed?(String.t() | nil) :: boolean()
  def repo_backed?(purl_type) do
    default_version_type(purl_type) == :git or purl_type in @repo_backed or
      Map.has_key?(@collection_urls, purl_type)
  end

  @doc """
  Casts authored input to a purl type string, rejecting anything the purl spec
  does not allow as a type (it must be a lowercase-normalized, non-empty
  segment without a slash or scheme separator).
  """
  @spec cast(term()) :: {:ok, String.t()} | :error
  def cast(purl_type) when is_atom(purl_type) and not is_nil(purl_type) do
    cast(Atom.to_string(purl_type))
  end

  def cast(purl_type) when is_binary(purl_type) do
    normalized = purl_type |> String.trim() |> String.downcase()

    if String.match?(normalized, ~r{^[a-z0-9][a-z0-9._-]*$}), do: {:ok, normalized}, else: :error
  end

  def cast(_purl_type), do: :error
end
