# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.InsertChildren do
  @moduledoc """
  Creates the channels and version boundary facts authored inline on a
  `propose_affected_package` insert, once the package row exists — through the
  children's regular `:add` actions inside the create's transaction (same
  actor, same policies, same paper trail), so accepting one package proposal
  materializes the whole product at once.

  The nested version events are package-global; a channel-scoped event
  (`package_channel_id`) is not expressible inline (see
  `Varsel.Cases.VersionEvent.EventInput`).
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.VersionEvent

  @impl Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, &create_children(&1, &2, context.actor))
  end

  defp create_children(changeset, package, actor) do
    channels = Ash.Changeset.get_argument(changeset, :channels) || []
    version_events = Ash.Changeset.get_argument(changeset, :version_events) || []

    children =
      Enum.map(channels, &child(PackageChannel, package, &1, actor)) ++
        Enum.map(version_events, &child(VersionEvent, package, &1, actor))

    Enum.reduce_while(children, {:ok, package, []}, fn child, {:ok, package, notifications} ->
      case Ash.create(child, return_notifications?: true) do
        {:ok, _row, new_notifications} ->
          {:cont, {:ok, package, notifications ++ new_notifications}}

        {:error, error} ->
          {:halt, {:error, error}}
      end
    end)
  end

  defp child(resource, package, params, actor) do
    params = Map.merge(params, %{case_id: package.case_id, affected_package_id: package.id})
    Ash.Changeset.for_create(resource, :add, params, actor: actor)
  end
end
