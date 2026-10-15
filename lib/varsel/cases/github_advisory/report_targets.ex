# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.ReportTargets do
  @moduledoc """
  The repositories a case can be reported to on GitHub: those of its
  affected packages that live on github.com, each with what the person
  looking can do there (`Varsel.GitHub.Credentials.reach/3`) and whether it
  takes private vulnerability reports, asked of GitHub with their
  credential for it.
  """

  alias Varsel.Accounts.User
  alias Varsel.Cases.Case
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.Credentials

  @type repository :: %{owner: String.t(), repo: String.t()}

  @typedoc """
  A repository, what the viewer can do there, and whether it takes private
  reports, or `:unknown` when GitHub did not say.
  """
  @type target :: %{
          owner: String.t(),
          repo: String.t(),
          reach: Credentials.reach(),
          private_reporting: boolean() | :unknown
        }

  @doc """
  The GitHub repositories of the case's loaded affected packages, in package
  order, each once.
  """
  @spec repositories(Case.t()) :: [repository()]
  def repositories(%Case{affected_packages: packages}) when is_list(packages) do
    packages |> Enum.flat_map(&repository/1) |> Enum.uniq()
  end

  defp repository(%{repo_url: url}) when not is_nil(url) do
    with %URI{host: "github.com", path: path} when is_binary(path) <- URI.parse(to_string(url)),
         [owner, repo | _rest] <- String.split(path, "/", trim: true) do
      [%{owner: owner, repo: String.replace_suffix(repo, ".git", "")}]
    else
      _other -> []
    end
  end

  defp repository(_package), do: []

  @doc """
  Each of `repositories` with what `actor` can do there and whether it
  takes private reports, asked of GitHub with their credential for it.
  """
  @spec list([repository()], User.t() | nil) :: [target()]
  def list(repositories, actor) do
    Enum.map(repositories, fn %{owner: owner, repo: repo} = repository ->
      Map.merge(repository, %{
        reach: Credentials.reach(actor, owner, repo),
        private_reporting: private_reporting(repository, actor)
      })
    end)
  end

  defp private_reporting(%{owner: owner, repo: repo}, actor) do
    case Credentials.run(
           actor,
           owner,
           repo,
           &Advisories.private_reporting_enabled?(owner, repo, token: &1.token)
         ) do
      {_kind, {:ok, enabled?}} -> enabled?
      _unknown -> :unknown
    end
  end
end
