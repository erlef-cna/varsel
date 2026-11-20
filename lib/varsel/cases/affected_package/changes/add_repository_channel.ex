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
  alias Varsel.Cases.AffectedPackage.Changes.ManageChildren
  alias Varsel.Cases.PackageChannel.PurlType

  @impl Change
  def change(changeset, _opts, _context) do
    ManageChildren.manage_deferred(changeset, fn changeset ->
      repo_url = Ash.Changeset.get_attribute(changeset, :repo_url)

      [channels: List.wrap(params(repo_url))]
    end)
  end

  @doc """
  The `:add` params of a package's repository channel, or nil without a
  `repo_url`.
  """
  @spec params(String.t() | nil) :: map() | nil
  def params(nil), do: nil

  def params(repo_url) do
    {purl_type, namespace, name, qualifiers} = PurlType.for_repository(repo_url)

    %{
      kind: :package,
      purl_type: purl_type,
      namespace: namespace,
      name: name,
      qualifiers: qualifiers,
      version_type: :git
    }
  end
end
