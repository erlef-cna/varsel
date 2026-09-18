# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.ReportTargets do
  @moduledoc """
  The repositories a case can be reported to on GitHub: those of its
  affected packages that live on github.com, each with whether it takes
  private vulnerability reports, asked of GitHub as the person looking.
  """

  alias Varsel.Accounts.User
  alias Varsel.Cases.Case
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.UserToken

  @type repository :: %{owner: String.t(), repo: String.t()}

  @typedoc "A repository and whether it takes private reports, or `:unknown` when GitHub did not say."
  @type target :: %{owner: String.t(), repo: String.t(), private_reporting: boolean() | :unknown}

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

  @doc "Each of `repositories` with whether it takes private reports, asked of GitHub as `actor`."
  @spec list([repository()], User.t() | nil) :: [target()]
  def list(repositories, actor) do
    token = UserToken.available(actor)
    Enum.map(repositories, &Map.put(&1, :private_reporting, private_reporting(&1, token)))
  end

  defp private_reporting(%{owner: owner, repo: repo}, token) do
    case Advisories.private_reporting_enabled?(owner, repo, token: token) do
      {:ok, enabled?} -> enabled?
      _unknown -> :unknown
    end
  end
end
