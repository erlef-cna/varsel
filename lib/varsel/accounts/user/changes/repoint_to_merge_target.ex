# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.RepointToMergeTarget do
  @moduledoc """
  Hands every row that references the account being merged away to the
  account it merges into, before the destroy deletes it: its linked providers,
  API keys, assignments, credits, comments, comment reactions, proposals,
  reports, notifications, GitHub installations and manual requests.

  Paper-trail versions are not foreign keys
  (`Varsel.Accounts.VersionActorReference`) and keep the id of the account
  that acted.
  """

  use Ash.Resource.Change

  import Ecto.Query

  alias Varsel.Accounts.ApiKey
  alias Varsel.Accounts.User
  alias Varsel.Accounts.UserIdentity
  alias Varsel.Cases.CaseAssignment
  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.Comment
  alias Varsel.Cases.CommentReaction
  alias Varsel.Cases.GitHubManualRequest
  alias Varsel.Cases.Proposal
  alias Varsel.Cases.VulnerabilityReport
  alias Varsel.GitHub.UserInstallation
  alias Varsel.Notifications.Notification
  alias Varsel.Repo

  @references [
    {UserIdentity, :user_id},
    {ApiKey, :user_id},
    {CaseAssignment, :user_id},
    {CaseCredit, :user_id},
    {Comment, :author_id},
    {CommentReaction, :user_id},
    {Proposal, :author_id},
    {Proposal, :resolved_by_id},
    {VulnerabilityReport, :reporter_id},
    {Notification, :user_id},
    {UserInstallation, :user_id},
    {GitHubManualRequest, :user_id}
  ]

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    into_id = Ash.Changeset.get_argument(changeset, :into_id)

    if into_id == changeset.data.id do
      Ash.Changeset.add_error(changeset, field: :into_id, message: "must name another account")
    else
      Ash.Changeset.before_action(changeset, &repoint_into(&1, into_id, context))
    end
  end

  defp repoint_into(changeset, into_id, context) do
    case Ash.get(User, into_id, Ash.Context.to_opts(context)) do
      {:ok, _into} ->
        repoint(changeset.data.id, into_id)
        changeset

      {:error, _not_found} ->
        Ash.Changeset.add_error(changeset, field: :into_id, message: "names no account")
    end
  end

  defp repoint(from_id, into_id) do
    drop_duplicates(from_id, into_id)
    drop_duplicate_reactions(from_id, into_id)

    Enum.each(@references, fn {schema, field} ->
      Repo.update_all(from(row in schema, where: field(row, ^field) == ^from_id),
        set: [{field, into_id}]
      )
    end)
  end

  # A row that would collide with a unique one the surviving account already
  # holds goes with the merged account instead.
  defp drop_duplicates(from_id, into_id) do
    Repo.delete_all(
      from(merged in CaseAssignment,
        as: :merged,
        where: merged.user_id == ^from_id,
        where:
          exists(
            from(kept in CaseAssignment,
              where: kept.user_id == ^into_id and kept.case_id == parent_as(:merged).case_id
            )
          )
      )
    )

    Repo.delete_all(
      from(merged in UserInstallation,
        as: :merged,
        where: merged.user_id == ^from_id,
        where:
          exists(
            from(kept in UserInstallation,
              where:
                kept.user_id == ^into_id and
                  kept.installation_id == parent_as(:merged).installation_id
            )
          )
      )
    )

    Repo.delete_all(
      from(merged in Notification,
        as: :merged,
        where: merged.user_id == ^from_id and is_nil(merged.read_at),
        where:
          exists(
            from(kept in Notification,
              where:
                kept.user_id == ^into_id and is_nil(kept.read_at) and
                  kept.kind == parent_as(:merged).kind and
                  fragment(
                    "? IS NOT DISTINCT FROM ?",
                    kept.case_id,
                    parent_as(:merged).case_id
                  )
            )
          )
      )
    )
  end

  defp drop_duplicate_reactions(from_id, into_id) do
    Repo.delete_all(
      from(merged in CommentReaction,
        as: :merged,
        where: merged.user_id == ^from_id,
        where:
          exists(
            from(kept in CommentReaction,
              where:
                kept.user_id == ^into_id and kept.comment_id == parent_as(:merged).comment_id and
                  kept.emoji == parent_as(:merged).emoji
            )
          )
      )
    )
  end
end
