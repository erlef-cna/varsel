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

    changeset
    |> stamp_constants(preset)
    |> stamp_default_status()
    |> ManageChildren.manage_deferred(&children(&1, preset))
  end

  # erlang/otp's history starts at a squashed import, so nothing below the root
  # commit is derivable.
  defp stamp_default_status(changeset) do
    introduced = Ash.Changeset.get_argument(changeset, :introduced_commit)

    if not stated?(changeset, :default_status) and is_binary(introduced) and
         Preset.otp_root_commit?(introduced) do
      Ash.Changeset.force_change_attribute(changeset, :default_status, :unknown)
    else
      changeset
    end
  end

  # An attribute carrying a `default` is already populated by the time a change
  # runs, so `get_attribute` cannot tell a stated value from a defaulted one.
  defp stated?(%{params: params}, field) do
    Map.has_key?(params, field) or Map.has_key?(params, to_string(field))
  end

  defp children(changeset, preset) do
    applications = Ash.Changeset.get_argument(changeset, :applications)
    repository = AddRepositoryChannel.params(Ash.Changeset.get_attribute(changeset, :repo_url))

    [
      channels: Preset.channels(preset, applications) ++ List.wrap(repository),
      version_events: events(changeset)
    ]
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
