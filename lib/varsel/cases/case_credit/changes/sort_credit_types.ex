# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseCredit.Changes.SortCreditTypes do
  @moduledoc """
  Stores a credit's types once each, in vocabulary order
  (`Varsel.Cases.CaseCredit.CreditType.sort/1`), so two credits with the
  same roles compare equal.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases.CaseCredit.CreditType

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    case Changeset.fetch_change(changeset, :credit_types) do
      {:ok, types} when is_list(types) ->
        Changeset.force_change_attribute(changeset, :credit_types, CreditType.sort(types))

      _unchanged ->
        changeset
    end
  end
end
