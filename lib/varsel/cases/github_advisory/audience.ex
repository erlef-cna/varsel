# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Audience do
  @moduledoc """
  Who sees a linked advisory on GitHub, asked as the person looking: the
  collaborators the advisory names, the members of each team it names, and
  the owners of the organization its repository lives under.

  Each list is asked with the credential `Varsel.GitHub.Credentials` gives
  the viewer for the advisory's repository. GitHub lists a team's members
  and an organization's owners to a token that can read the organization's
  members: a member's own token, or the installation token of the App on
  that organization. A group the viewer cannot list is `:unknown`.
  """

  alias Varsel.Accounts.User
  alias Varsel.Cases.GitHubAdvisory
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.GitHub.Credentials
  alias Varsel.GitHub.Organizations

  @typedoc "The logins of a group, or `:unknown` when the viewer cannot list it."
  @type logins :: [String.t()] | :unknown

  @type team :: %{slug: String.t(), members: logins()}

  @type t :: %{users: [String.t()], teams: [team()], owners: logins()}

  @doc "Who sees the advisory of `link`, as `actor`."
  @spec resolve(GitHubAdvisoryLink.t(), User.t() | nil) :: t()
  def resolve(%GitHubAdvisoryLink{} = link, actor) do
    summary = GitHubAdvisory.summary(link.advisory)

    %{
      users: summary.collaborators,
      teams: Enum.map(summary.teams, &%{slug: &1, members: members(link, &1, actor)}),
      owners: owners(link, actor)
    }
  end

  # GitHub answers 404 for an account that is no organization, and a
  # repository under a user account has that user as its owner.
  defp owners(%{owner: owner, repo: repo}, actor) when is_binary(owner) and is_binary(repo) do
    case Credentials.run(actor, owner, repo, &Organizations.owners(owner, token: &1.token)) do
      {_kind, {:ok, logins}} -> logins
      {_kind, :not_found} -> [owner]
      _unreadable -> :unknown
    end
  end

  defp owners(_global_entry, _actor), do: :unknown

  defp members(%{owner: owner, repo: repo}, slug, actor) when is_binary(owner) and is_binary(repo) do
    case Credentials.run(
           actor,
           owner,
           repo,
           &Organizations.team_members(owner, slug, token: &1.token)
         ) do
      {_kind, {:ok, logins}} -> logins
      _unreadable -> :unknown
    end
  end

  defp members(_global_entry, _slug, _actor), do: :unknown
end
