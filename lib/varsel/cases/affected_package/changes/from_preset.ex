# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.FromPreset do
  @moduledoc """
  Backs the specialized preset create actions on
  `Varsel.Cases.AffectedPackage`: stamps the preset's package constants and
  spawns its distribution channels (the repository's own included) and the
  version boundary facts from the given commits — all inside the create's
  transaction, through the children's regular `:add` actions (same actor, same
  policies, same paper trail).
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Cases.AffectedPackage.Changes.AddRepositoryChannel
  alias Varsel.Cases.AffectedPackage.Changes.ManageChildren
  alias Varsel.Cases.AffectedPackage.Preset

  @impl Change
  def init(opts) do
    if opts[:preset] in Preset.values() do
      {:ok, opts}
    else
      {:error, "preset must be one of #{inspect(Preset.values())}"}
    end
  end

  @impl Change
  def change(changeset, opts, _context) do
    preset = opts[:preset]
    changeset = stamp_constants(changeset, preset)

    # Children are built up front now, so a preset that takes applications must
    # wait for the argument's own validation to reject a missing list rather
    # than expanding nil into channels.
    if Preset.applications?(preset) and
         is_nil(Ash.Changeset.get_argument(changeset, :applications)) do
      changeset
    else
      manage_children(changeset, preset)
    end
  end

  defp manage_children(changeset, preset) do
    applications = Ash.Changeset.get_argument(changeset, :applications)
    repository = AddRepositoryChannel.params(Ash.Changeset.get_attribute(changeset, :repo_url))

    changeset
    |> ManageChildren.manage(
      :channels,
      Preset.channels(preset, applications) ++ List.wrap(repository)
    )
    |> ManageChildren.manage(:version_events, events(changeset))
  end

  defp stamp_constants(changeset, preset) do
    Enum.reduce(Preset.attributes(preset), changeset, fn {attribute, value}, changeset ->
      Ash.Changeset.force_change_attribute(changeset, attribute, value)
    end)
  end

  defp events(changeset) do
    introduced = Ash.Changeset.get_argument(changeset, :introduced_commit)
    fixed = Ash.Changeset.get_argument(changeset, :fixed_commits) || []

    List.wrap(if introduced, do: %{event: :introduced, commit_sha: introduced}) ++
      Enum.map(fixed, &%{event: :fixed, commit_sha: &1})
  end
end
