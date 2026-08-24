# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Validations.UniquePreferenceKinds do
  @moduledoc """
  Validates that `notification_preferences` carries at most one entry per
  kind, so `Varsel.Notifications.Preference.for_kind/2` has exactly one row
  to find.
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    preferences = Ash.Changeset.get_attribute(changeset, :notification_preferences) || []
    kinds = Enum.map(preferences, & &1.kind)

    case kinds -- Enum.uniq(kinds) do
      [] ->
        :ok

      duplicates ->
        {:error,
         field: :notification_preferences,
         message: "has more than one entry for kind: %{duplicates}",
         vars: [duplicates: duplicates |> Enum.uniq() |> Enum.join(", ")]}
    end
  end
end
