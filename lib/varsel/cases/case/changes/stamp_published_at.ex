# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.StampPublishedAt do
  @moduledoc """
  Sets `published_at` on the first successful publish; amendments keep the
  original timestamp.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(%{data: %{published_at: %DateTime{}}} = changeset, _opts, _context), do: changeset

  def change(changeset, _opts, _context), do: Ash.Changeset.change_attribute(changeset, :published_at, DateTime.utc_now())
end
