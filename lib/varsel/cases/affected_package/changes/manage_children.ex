# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.ManageChildren do
  @moduledoc """
  Manages a package's child rows (channels, version boundary facts) as part of
  the package's own create, for the paths that spawn children alongside it:
  the presets and inline proposal payloads.

  Each row goes in through its resource's regular `:add` action, so the
  validations and policies that apply to a POC adding it by hand apply here
  too, and Ash keeps the whole thing in one transaction.
  """

  @doc """
  Adds `rows` to the package's `relationship`, leaving the changeset untouched
  when there are none.
  """
  @spec manage(Ash.Changeset.t(), atom(), [map()]) :: Ash.Changeset.t()
  def manage(changeset, _relationship, []), do: changeset

  def manage(changeset, relationship, rows) do
    # `case_id` is denormalized onto the children rather than reached through
    # the package, so the relationship cannot stamp it the way it does
    # `affected_package_id`.
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)
    rows = Enum.map(rows, &Map.put(&1, :case_id, case_id))

    Ash.Changeset.manage_relationship(changeset, relationship, rows,
      type: :create,
      on_no_match: {:create, :add}
    )
  end
end
