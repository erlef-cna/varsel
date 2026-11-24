# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.DefaultDatePublic do
  @moduledoc """
  Gives a `date_public` nobody set the publish instant: the publish is the
  disclosure. The record sent to MITRE carries the same value as the case.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(%{data: %{date_public: nil}} = changeset, _opts, _context),
    do: Ash.Changeset.change_attribute(changeset, :date_public, DateTime.utc_now())

  def change(changeset, _opts, _context), do: changeset
end
