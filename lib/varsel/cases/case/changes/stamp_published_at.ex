# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.StampPublishedAt do
  @moduledoc """
  Sets `published_at` on the first successful publish; amendments keep the
  original timestamp. A `date_public` nobody set gets the same instant: the
  publish is the disclosure.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(%{data: %{published_at: %DateTime{}}} = changeset, _opts, _context), do: changeset

  def change(changeset, _opts, _context) do
    now = DateTime.utc_now()

    changeset
    |> Ash.Changeset.change_attribute(:published_at, now)
    |> default_date_public(now)
  end

  defp default_date_public(%{data: %{date_public: nil}} = changeset, now),
    do: Ash.Changeset.change_attribute(changeset, :date_public, now)

  defp default_date_public(changeset, _now), do: changeset
end
