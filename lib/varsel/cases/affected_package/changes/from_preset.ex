# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.FromPreset do
  @moduledoc """
  Backs the specialized preset create actions on
  `Varsel.Cases.AffectedPackage`: stamps the preset's package constants and,
  once the package row exists, spawns its distribution channels and the
  version boundary facts from the given commits — all inside the create's
  transaction, through the children's regular `:add` actions (same actor,
  same policies, same paper trail).
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.VersionEvent

  @impl Change
  def init(opts) do
    if opts[:preset] in Preset.values() do
      {:ok, opts}
    else
      {:error, "preset must be one of #{inspect(Preset.values())}"}
    end
  end

  @impl Change
  def change(changeset, opts, context) do
    preset = opts[:preset]

    changeset
    |> stamp_constants(preset)
    |> Ash.Changeset.after_action(&create_children(&1, &2, preset, context.actor))
  end

  defp stamp_constants(changeset, preset) do
    Enum.reduce(Preset.attributes(preset), changeset, fn {attribute, value}, changeset ->
      Ash.Changeset.force_change_attribute(changeset, attribute, value)
    end)
  end

  defp create_children(changeset, package, preset, actor) do
    applications = Ash.Changeset.get_argument(changeset, :applications)

    children =
      Enum.map(Preset.channels(preset, applications), &child(PackageChannel, package, &1, actor)) ++
        Enum.map(events(changeset), &child(VersionEvent, package, &1, actor))

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

  defp events(changeset) do
    introduced = Ash.Changeset.get_argument(changeset, :introduced_commit)
    fixed = Ash.Changeset.get_argument(changeset, :fixed_commits) || []

    List.wrap(if introduced, do: %{event: :introduced, commit_sha: introduced}) ++
      Enum.map(fixed, &%{event: :fixed, commit_sha: &1})
  end
end
