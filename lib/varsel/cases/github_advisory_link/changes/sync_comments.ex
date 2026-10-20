# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink.Changes.SyncComments do
  @moduledoc """
  Reads the comments on the linked advisory and records the ones the case
  does not hold, then stamps `comments_polled_at`.

  The read asks GitHub only for what changed since the last poll, and runs
  with the App's installation token on the advisory's repository. No person
  is asking, so `Varsel.GitHub.Credentials` has no personal token to prefer
  and takes no part: the installation is looked up and its token minted
  directly. Where the App is not installed, there is no token and the poll
  records nothing.

  GitHub answers an empty list to a caller who may see the advisory but not
  its discussion, so an empty answer stamps the poll without concluding the
  discussion is empty.

  A link to a global database entry names no repository and has no
  discussion to read, so it is stamped and left alone.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Error.Unknown.UnknownError
  alias Varsel.Cases
  alias Varsel.GitHub
  alias Varsel.GitHub.Advisories
  alias Varsel.Service

  require Logger

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    # What the poll asks GitHub for is what the row said before this write,
    # which the new stamp is about to replace.
    since = changeset.data.comments_polled_at

    changeset
    |> Changeset.force_change_attribute(:comments_polled_at, DateTime.utc_now())
    |> Changeset.after_action(&record(&1, &2, since, context))
  end

  defp record(_changeset, %{owner: owner, repo: repo} = link, since, context) when is_binary(owner) and is_binary(repo) do
    case token(link) do
      {:ok, token} -> read(link, token, since, context)
      :none -> {:ok, link}
    end
  end

  defp record(_changeset, link, _since, _context), do: {:ok, link}

  defp read(link, token, since, context) do
    case Advisories.list_comments(link.owner, link.repo, link.ghsa_id,
           token: token,
           since: since
         ) do
      {:ok, comments} ->
        store(comments, link, context)

      :not_found ->
        {:ok, link}

      {:error, reason} ->
        {:error,
         UnknownError.exception(error: "Could not read the comments of #{link.ghsa_id} from GitHub: #{inspect(reason)}")}
    end
  end

  defp token(link) do
    actor = Service.github_comment_sync()

    with %{id: id} <-
           GitHub.installation_for_repository!(link.owner, link.repo, actor: actor),
         {:ok, token} <- GitHub.installation_token(id, actor: actor) do
      {:ok, token}
    else
      nil ->
        :none

      {:error, error} ->
        Logger.info("No installation token to read the comments of #{link.ghsa_id}: #{inspect(error)}")

        :none
    end
  end

  # Each comment is written on its own: one GitHub body the case will not
  # take must not stop the rest of the discussion from arriving.
  defp store(comments, link, context) do
    opts =
      context
      |> Varsel.ObanContext.forward()
      |> Keyword.put(:actor, Service.github_comment_sync())

    Enum.each(comments, fn comment ->
      case Cases.sync_case_comment_from_github(input(comment, link), opts) do
        {:ok, _comment} ->
          :ok

        {:error, error} ->
          Logger.warning(
            "Skipped advisory comment #{inspect(comment["id"])} of #{link.ghsa_id}: #{Exception.message(error)}"
          )
      end
    end)

    {:ok, link}
  end

  defp input(comment, link) do
    %{
      case_id: link.case_id,
      body: comment["body"],
      github_comment_id: comment["id"],
      github_author_login: get_in(comment, ["user", "login"]),
      github_html_url: comment["html_url"]
    }
  end
end
