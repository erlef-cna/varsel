# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.InsertChildren do
  @moduledoc """
  Creates the channels and version boundary facts authored inline on a
  `propose_affected_package` insert — through the children's regular `:add`
  actions inside the create's transaction (same actor, same policies, same
  paper trail), so accepting one package proposal materializes the whole
  product at once. The repository's own channel comes along too, as it would on
  a direct `:add`.

  The nested version events are package-global; a channel-scoped event
  (`package_channel_id`) is not expressible inline (see
  `Varsel.Cases.VersionEvent.EventInput`).
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Cases.AffectedPackage.Changes.AddRepositoryChannel
  alias Varsel.Cases.AffectedPackage.Changes.ManageChildren

  @impl Change
  def change(changeset, _opts, _context) do
    ManageChildren.manage_deferred(changeset, &children/1)
  end

  defp children(changeset) do
    authored = Ash.Changeset.get_argument(changeset, :channels) || []
    repository = AddRepositoryChannel.params(Ash.Changeset.get_attribute(changeset, :repo_url))

    [
      channels: authored ++ List.wrap(repository),
      version_events: Ash.Changeset.get_argument(changeset, :version_events) || []
    ]
  end
end
