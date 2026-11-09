# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.InheritFromSource do
  @moduledoc """
  Fills the `:reports`, `:assignments` and `:invites` arguments with what the
  case named by `:source_case_id` holds, for the action's
  `manage_relationship` changes to write. People already on the case are
  left out.

  The reports go in as the records the source case loaded, so the citation
  relates them as read through that case rather than looking each one up
  again under the report's own read policy.

  A person without an account yet is invited in their own right, so the
  invite emails them as any invite would.

  With `open_source?: true`, a source that is closed or merged is refused.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases

  @impl Ash.Resource.Change
  def change(changeset, opts, context) do
    read_opts = Ash.Context.to_opts(context)
    source_case_id = Changeset.get_argument(changeset, :source_case_id)
    open_source? = opts[:open_source?] == true

    case Cases.get_case(
           source_case_id,
           [load: [:vulnerability_reports, :assignments, :invites]] ++ read_opts
         ) do
      {:ok, %{state: state}} when open_source? and state in [:closed, :merged] ->
        Changeset.add_error(changeset, field: :source_case_id, message: "is #{state}")

      {:ok, source} ->
        inherit(changeset, source, on_case(changeset, read_opts))

      {:error, _error} ->
        Changeset.add_error(changeset, field: :source_case_id, message: "does not exist")
    end
  end

  defp inherit(changeset, source, on_case) do
    changeset
    |> Changeset.set_argument(:reports, source.vulnerability_reports)
    |> Changeset.set_argument(:assignments, assignments(source, on_case))
    |> Changeset.set_argument(:invites, invites(source, on_case))
  end

  defp assignments(source, %{users: users}) do
    for assignment <- source.assignments, assignment.user_id not in users do
      %{user_id: assignment.user_id, note: assignment.note}
    end
  end

  defp invites(source, %{handles: handles}) do
    for invite <- source.invites, handle(invite) not in handles do
      %{
        strategy: invite.strategy,
        username: to_string(invite.username),
        note: invite.note,
        role: invite.role,
        email_optional: true
      }
    end
  end

  defp on_case(%{action_type: :create}, _read_opts), do: %{users: [], handles: []}

  defp on_case(changeset, read_opts) do
    target = Ash.load!(changeset.data, [:assignments, :invites], read_opts)

    %{
      users: Enum.map(target.assignments, & &1.user_id),
      handles: Enum.map(target.invites, &handle/1)
    }
  end

  defp handle(invite), do: {invite.strategy, invite.username |> to_string() |> String.downcase()}
end
