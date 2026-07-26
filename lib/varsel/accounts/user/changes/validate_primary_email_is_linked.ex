# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.ValidatePrimaryEmailIsLinked do
  @moduledoc """
  Refuses a primary email that none of the account's linked providers reported.

  The set of addresses a user may choose from is exactly what their providers
  have told us about them. Without this check `:set_primary_email` would be a
  free-text email field, letting anyone claim an address they do not own — and
  the unique index would then hand them a permanent squat on it.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, &validate(&1, context))
  end

  defp validate(changeset, context) do
    case Ash.Changeset.get_attribute(changeset, :email) do
      nil ->
        changeset

      email ->
        if email in linked_emails(changeset, context) do
          changeset
        else
          Ash.Changeset.add_error(changeset,
            field: :email,
            message: "is not an address any linked provider reported"
          )
        end
    end
  end

  defp linked_emails(changeset, context) do
    changeset.data
    |> Ash.load!([:identities], Ash.Context.to_opts(context))
    |> Map.fetch!(:identities)
    |> Enum.map(& &1.email)
    |> Enum.reject(&is_nil/1)
  end
end
