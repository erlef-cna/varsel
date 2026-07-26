# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.RepointToMergeTarget do
  @moduledoc """
  Hands everything the merged account still holds to the account it merged
  into: its linked providers, its API keys, and every place it appears as a
  working party — assignments, credits, comments, proposals, reports.

  Live state has to move or it strands. An assignment pointing at an account
  nobody can sign into is work nobody can pick up, and an API key on it would
  authenticate as a user who no longer exists in any useful sense.

  Paper-trail versions deliberately stay behind. They record who did something
  at the time, which merging does not change; the tombstone on the merged row
  (`merged_into`) is what resolves that author to the surviving account.
  """

  use Ash.Resource.Change

  # Every live reference to a user, written out in full rather than built from
  # a table/column list — these are constants, and spelling them out keeps any
  # runtime value out of the statement entirely.
  #
  # SQL rather than each resource's own actions: this is a bulk repoint, and
  # running it through (say) the proposal update action would fire
  # notifications and policy checks for something that is not a domain event.
  @repoint_statements [
    "UPDATE user_identities SET user_id = $1 WHERE user_id = $2",
    "UPDATE api_keys SET user_id = $1 WHERE user_id = $2",
    "UPDATE case_assignments SET user_id = $1 WHERE user_id = $2",
    "UPDATE case_credits SET user_id = $1 WHERE user_id = $2",
    "UPDATE case_comments SET author_id = $1 WHERE author_id = $2",
    "UPDATE case_proposals SET author_id = $1 WHERE author_id = $2",
    "UPDATE case_proposals SET resolved_by_id = $1 WHERE resolved_by_id = $2",
    "UPDATE vulnerability_reports SET reporter_id = $1 WHERE reporter_id = $2"
  ]

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.after_action(changeset, fn changeset, merged ->
      repoint(merged.id, Ash.Changeset.get_attribute(changeset, :merged_into_id))
      {:ok, merged}
    end)
  end

  # Every statement is a literal from the list above; the only runtime values
  # are the two ids, which are bound as parameters.
  # sobelow_skip ["SQL.Query"]
  defp repoint(from_id, into_id) do
    params = [Ecto.UUID.dump!(into_id), Ecto.UUID.dump!(from_id)]

    Enum.each(@repoint_statements, fn statement ->
      Varsel.Repo.query!(statement, params)
    end)
  end
end
