# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Changes.NormalizePackageName do
  @moduledoc """
  Git channels name the package by its in-forge path ("owner/repo"). People
  paste clone URLs; normalize them on write so the stored name is the path,
  never a URL (which would otherwise render into a percent-encoded purl).
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Render.Channel

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    with :git <- Ash.Changeset.get_attribute(changeset, :channel_type),
         name when is_binary(name) <- Ash.Changeset.get_attribute(changeset, :package_name) do
      Ash.Changeset.change_attribute(changeset, :package_name, Channel.forge_path(name))
    else
      _other -> changeset
    end
  end
end
