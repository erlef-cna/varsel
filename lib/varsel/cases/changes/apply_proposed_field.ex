# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Changes.ApplyProposedField do
  @moduledoc """
  Change behind every `:apply_proposal` action: sets the single field named by
  the `field` argument to the `value` argument, restricted to the resource's
  `Varsel.Cases.Proposable.set_fields/1` allowlist.

  The value passes through the attribute's own Ash type cast, so an invalid
  value fails the accept transaction rather than corrupting the row.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Proposable

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    field = Ash.Changeset.get_argument(changeset, :field)
    value = Ash.Changeset.get_argument(changeset, :value)
    allowed = Proposable.set_fields(changeset.resource)

    with {:ok, field_atom} <- existing_atom(field),
         true <- field_atom in allowed do
      Ash.Changeset.change_attribute(changeset, field_atom, value)
    else
      _ ->
        Ash.Changeset.add_error(changeset,
          field: :field,
          message: "#{field} is not a proposable field of #{inspect(changeset.resource)}"
        )
    end
  end

  defp existing_atom(field) when is_binary(field) do
    {:ok, String.to_existing_atom(field)}
  rescue
    ArgumentError -> :error
  end

  defp existing_atom(field) when is_atom(field), do: {:ok, field}
end
