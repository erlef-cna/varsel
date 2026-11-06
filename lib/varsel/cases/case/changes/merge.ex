# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.Merge do
  @moduledoc """
  Behind `Varsel.Cases.Case`'s `:merge`. Points the case at the case it merges
  into, once that case is one the actor can read and still open. The
  `:case_merged` signal carries the reports and people over.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    opts = Ash.Context.to_opts(context)

    Changeset.before_action(changeset, fn changeset ->
      into_case_id = Changeset.get_argument(changeset, :into_case_id)

      case target(changeset.data, into_case_id, opts) do
        {:ok, target} ->
          Changeset.force_change_attribute(changeset, :merged_into_id, target.id)

        {:error, message} ->
          Changeset.add_error(changeset, field: :into_case_id, message: message)
      end
    end)
  end

  defp target(%{id: id}, id, _opts), do: {:error, "cannot be the case itself"}

  defp target(_source, into_case_id, opts) do
    case Cases.get_case(into_case_id, opts) do
      {:ok, %{state: state}} when state in [:closed, :merged] -> {:error, "is #{state}"}
      {:ok, target} -> {:ok, target}
      {:error, _error} -> {:error, "does not exist"}
    end
  end
end
