# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.AddRepositoryChannel do
  @moduledoc """
  Creates the source repository's own distribution channel when a package is
  added with a `repo_url`.

  The repository is a place the affected code is obtained from like any other,
  so it is a stored `Varsel.Cases.PackageChannel` — editable, removable, and
  rendered through the one channel path — rather than an entry the renderer
  conjures. `Varsel.Cases.PackageChannel.PurlType.for_repository/1` decides its
  purl identity (`pkg:github/...` and friends where the forge has a registered
  type, `pkg:generic` carrying `vcs_url` where it does not).

  A package without a `repo_url` gets nothing: a service has no repository to
  publish.
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Cases.PackageChannel.PurlType

  # Far past any hand-authored channel's position, so the repository sorts last
  # without having to renumber the ones added after it.
  @repository_position 1_000

  @impl Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, &create_channel(&1, &2, context.actor))
  end

  @doc """
  The `:add` params of a package's repository channel, or nil without a
  `repo_url`.

  `position` defaults high so the repository closes the package's entries
  (registries first, source last, as the published records read) even though it
  is created before the registry channels that will precede it.
  """
  @spec params(String.t() | nil, non_neg_integer()) :: map() | nil
  def params(repo_url, position \\ @repository_position)

  def params(nil, _position), do: nil

  def params(repo_url, position) do
    {purl_type, namespace, name, qualifiers} = PurlType.for_repository(repo_url)

    %{
      kind: :package,
      purl_type: purl_type,
      namespace: namespace,
      name: name,
      qualifiers: qualifiers,
      version_type: :git,
      position: position
    }
  end

  defp create_channel(_changeset, %{repo_url: nil} = package, _actor), do: {:ok, package}

  defp create_channel(_changeset, package, actor) do
    params =
      package.repo_url
      |> params()
      |> Map.merge(%{case_id: package.case_id, affected_package_id: package.id})

    params
    |> Varsel.Cases.changeset_to_add_package_channel(actor: actor)
    |> Ash.create(return_notifications?: true)
    |> case do
      {:ok, _channel, notifications} -> {:ok, package, notifications}
      {:error, error} -> {:error, error}
    end
  end
end
