# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.PurlType do
  @moduledoc """
  A Package URL type — an *open* vocabulary, not an enum.

  Any purl type may be authored: casting accepts whatever the purl spec allows
  as a type (a non-empty segment of `[a-z0-9._-]`, no slash or scheme
  separator), normalized to lowercase. Publishing an advisory for an ecosystem
  we have never seen therefore needs a row, not a code change.

  Alongside the type itself, this module supplies the conventions of the types
  we know — their registry URL, how they version, whether they carry a
  namespace — and degrades to neutral answers for the ones we do not.

  Known-type knowledge is deliberately thin: it only covers what the rendered
  `affected[]` entry needs (`collectionURL`, `versionType`) plus the forge
  mapping the repository channel is derived through.

  Types absent from those tables still work — that is the point of an open
  vocabulary. `sid` (software without a registry, purl-spec decision 001) is
  one: it needs no entry, since it takes the neutral defaults. The spec has
  since renamed it, and we keep publishing `sid` until the final type lands —
  a change of stored data, not of code.

  Values are stored as `:string`, so an existing `:string` attribute can adopt
  this type without a migration.
  """

  @behaviour AshGraphql.Type

  use Ash.Type

  alias Varsel.Cases.PackageChannel.VersionType

  # What the purl spec allows as a type, after normalization.
  @format ~r{^[a-z0-9][a-z0-9._-]*$}

  # A string on the wire both ways — normalization is server-side, so a client
  # sends and receives the plain type.
  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :string

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :string

  @impl Ash.Type
  def storage_type(_constraints), do: :string

  @impl Ash.Type
  def cast_input(nil, _constraints), do: {:ok, nil}

  def cast_input(value, constraints) when is_atom(value) do
    value |> Atom.to_string() |> cast_input(constraints)
  end

  def cast_input(value, _constraints) when is_binary(value) do
    case cast(value) do
      {:ok, purl_type} -> {:ok, purl_type}
      :error -> {:error, message: "is not a valid purl type"}
    end
  end

  def cast_input(_value, _constraints), do: {:error, message: "is not a valid purl type"}

  # Stored values were normalized on the way in, so they are returned as-is.
  @impl Ash.Type
  def cast_stored(nil, _constraints), do: {:ok, nil}
  def cast_stored(value, _constraints) when is_binary(value), do: {:ok, value}
  def cast_stored(_value, _constraints), do: :error

  @impl Ash.Type
  def dump_to_native(nil, _constraints), do: {:ok, nil}
  def dump_to_native(value, _constraints) when is_binary(value), do: {:ok, value}
  def dump_to_native(_value, _constraints), do: :error

  @doc """
  Normalizes external input to a purl type string, rejecting anything the purl
  spec does not allow as one.
  """
  @spec cast(term()) :: {:ok, String.t()} | :error
  def cast(purl_type) when is_atom(purl_type) and not is_nil(purl_type) do
    cast(Atom.to_string(purl_type))
  end

  def cast(purl_type) when is_binary(purl_type) do
    normalized = purl_type |> String.trim() |> String.downcase()

    if String.match?(normalized, @format), do: {:ok, normalized}, else: :error
  end

  def cast(_purl_type), do: :error

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
end
