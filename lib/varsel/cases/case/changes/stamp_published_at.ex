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
  def change(changeset, _opts, _context) do
    if changeset.data.published_at do
      changeset
    else
      Ash.Changeset.change_attribute(changeset, :published_at, DateTime.utc_now())
    end
  end
end
