# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Audience do
  @moduledoc """
  Who sees a linked advisory on GitHub, asked as the person looking: the
  collaborators the advisory names, the members of each team it names, and
  the owners of the organization its repository lives under.

  GitHub lists a team's members and an organization's owners to a member of
  the organization whose token carries the `read:org` scope. A group the
  viewer cannot list is `:unknown`.
  """

  alias Varsel.Accounts.User
  alias Varsel.Cases.GitHubAdvisory
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.GitHub.Organizations
  alias Varsel.GitHub.UserToken

  @typedoc "The logins of a group, or `:unknown` when the viewer cannot list it."
  @type logins :: [String.t()] | :unknown

  @type team :: %{slug: String.t(), members: logins()}

  @type t :: %{users: [String.t()], teams: [team()], owners: logins()}

  @doc "Who sees the advisory of `link`, as `actor`."
  @spec resolve(GitHubAdvisoryLink.t(), User.t() | nil) :: t()
  def resolve(%GitHubAdvisoryLink{} = link, actor) do
    token = UserToken.available(actor)
    summary = GitHubAdvisory.summary(link.advisory)

    %{
      users: summary.collaborators,
      teams: Enum.map(summary.teams, &%{slug: &1, members: members(link.owner, &1, token)}),
      owners: owners(link.owner, token)
    }
  end

  # GitHub answers 404 for an account that is no organization, and a
  # repository under a user account has that user as its owner.
  defp owners(owner, token) when is_nil(owner) or is_nil(token), do: :unknown

  defp owners(owner, token) do
    case Organizations.owners(owner, token: token) do
      {:ok, logins} -> logins
      :not_found -> [owner]
      {:error, _reason} -> :unknown
    end
  end

  defp members(owner, _slug, token) when is_nil(owner) or is_nil(token), do: :unknown

  defp members(owner, slug, token) do
    case Organizations.team_members(owner, slug, token: token) do
      {:ok, logins} -> logins
      _unreadable -> :unknown
    end
  end
end
