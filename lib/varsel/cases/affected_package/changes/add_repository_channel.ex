# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.AddRepositoryChannel do
  @moduledoc """
  Gives a package added with a `repo_url` the source repository's own
  distribution channel.

  The repository is a place the affected code is obtained from like any other,
  so it is a stored `Varsel.Cases.PackageChannel` — editable, removable, and
  rendered through the one channel path — rather than an entry the renderer
  conjures. `Varsel.Cases.PackageChannel.PurlType.for_repository/1` decides its
  purl identity (`pkg:github/...` and friends where the forge has a registered
  type, `pkg:generic` carrying `vcs_url` where it does not).

  The row is managed through the package's `:channels` relationship and goes in
  through the channel's own `:add` action, so the validations and policies that
  apply to a POC adding it by hand apply here too. `params/2` is public because
  the preset and proposal paths assemble their children as one list rather than
  running this change (see
  `Varsel.Cases.AffectedPackage.Changes.FromPreset` and
  `Varsel.Cases.AffectedPackage.Changes.InsertChildren`).

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
  def change(changeset, _opts, _context) do
    case params(Ash.Changeset.get_attribute(changeset, :repo_url)) do
      nil ->
        changeset

      params ->
        # `case_id` is denormalized onto the channel rather than reached through
        # the package, so the relationship cannot stamp it the way it does
        # `affected_package_id`.
        params = Map.put(params, :case_id, Ash.Changeset.get_attribute(changeset, :case_id))

        Ash.Changeset.manage_relationship(changeset, :channels, [params],
          type: :create,
          on_no_match: {:create, :add}
        )
    end
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
end
