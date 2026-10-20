# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment.Changes.CrossPostToGitHub do
  @moduledoc """
  Writes a comment to the case's linked GitHub advisory when the author asked
  for it, and records where GitHub put it.

  The write runs with the author's own GitHub token where their login reaches
  the App's installation on the repository, so GitHub attributes the comment
  to them. Otherwise it runs with the installation token, which GitHub
  attributes to the App, and the body names the author instead. Every body
  carries the address of the case, since the discussion continues there.

  The write runs before the comment is stored and a refusal fails the action,
  so the case never shows a comment the advisory does not hold. An author who
  wants to comment while GitHub is unreachable leaves the cross-post
  unchecked.
  """

  use Ash.Resource.Change
  use VarselWeb, :verified_routes

  alias Ash.Changeset
  alias Ash.Resource.Change
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.Credentials

  require Ash.Query
  require Logger

  @impl Change
  def change(changeset, _opts, context) do
    if Changeset.get_argument(changeset, :cross_post) do
      Changeset.before_action(changeset, &post(&1, context))
    else
      changeset
    end
  end

  defp post(changeset, context) do
    with {:ok, link} <- link(changeset, context),
         {:ok, comment} <- write(changeset, link, context) do
      changeset
      |> Changeset.force_change_attribute(:github_html_url, comment.html_url)
      |> Changeset.force_change_attribute(:github_comment_id, comment.id)
    else
      {:error, message} -> refuse(changeset, message)
    end
  end

  ## ------------------------------------------------------------------ link

  defp link(changeset, context) do
    case_id = Changeset.get_attribute(changeset, :case_id)

    GitHubAdvisoryLink
    |> Ash.Query.filter(case_id == ^case_id)
    |> Ash.read_one(Ash.Context.to_opts(context))
    |> case do
      {:ok, %{owner: owner, repo: repo} = link} when is_binary(owner) and is_binary(repo) ->
        {:ok, link}

      {:ok, %{}} ->
        {:error, "names a GitHub advisory with no repository, which has no discussion to write to"}

      {:ok, nil} ->
        {:error, "has no linked GitHub advisory"}

      {:error, _error} ->
        {:error, "has no linked GitHub advisory this comment may be written to"}
    end
  end

  ## ----------------------------------------------------------------- write

  defp write(changeset, link, context) do
    actor = context.actor

    actor
    |> Credentials.run(link.owner, link.repo, fn credential ->
      Advisories.post_comment(
        link.owner,
        link.repo,
        link.ghsa_id,
        body(changeset, credential.kind, actor),
        token: credential.token
      )
    end)
    |> answer(link)
  end

  # The id GitHub gave the comment is what the poll keys on, so recording it
  # is what stops the poll reading this comment back as a second one.
  defp answer({_kind, {:ok, comment}}, _link) when is_map(comment),
    do: {:ok, %{id: comment["id"], html_url: comment["html_url"]}}

  defp answer({_kind, :not_found}, link),
    do: {:error, "could not be written to #{link.ghsa_id}: GitHub does not serve its discussion to us"}

  defp answer({_kind, {:error, :unauthorized}}, link),
    do: {:error, "could not be written to #{link.ghsa_id}: GitHub no longer accepts the credential"}

  # The author can act on neither GitHub's status code nor its body, and a
  # raw term in a form error reads as a crash. What they can act on is that
  # the comment is theirs to post again, or to post here alone.
  defp answer({_kind, {:error, reason}}, link) do
    Logger.warning("GitHub refused a comment on #{link.ghsa_id}: #{inspect(reason)}")

    {:error, "could not be written to #{link.ghsa_id}: GitHub refused it. Nothing was posted"}
  end

  defp answer({:no_credential, reason}, _link), do: {:error, Credentials.message(reason)}

  ## ------------------------------------------------------------------ body

  # GitHub attributes an installation write to the App, so the footer names
  # the person who wrote it. A write as the person is already theirs.
  defp body(changeset, :user, _actor), do: Changeset.get_attribute(changeset, :body) <> footer(changeset, nil)

  defp body(changeset, _installation, actor),
    do: Changeset.get_attribute(changeset, :body) <> footer(changeset, author_name(actor))

  # GitHub renders a subset of HTML in a comment, and `<sub>` is the one way
  # to set a line smaller than the body around it.
  defp footer(changeset, author) do
    link =
      "[Cross-posted from the EEF CNA case](#{url(~p"/cases/#{Changeset.get_attribute(changeset, :case_id)}")})"

    case author do
      nil -> "\n\n<sub>#{link}</sub>"
      name -> "\n\n<sub>#{link}, written by #{name}</sub>"
    end
  end

  defp author_name(actor) do
    case Ash.load(actor, :display_name, actor: actor) do
      {:ok, %{display_name: name}} when is_binary(name) -> name
      _unnamed -> "Someone"
    end
  end

  defp refuse(changeset, message) do
    Changeset.add_error(changeset, field: :cross_post, message: "This case " <> message)
  end
end
