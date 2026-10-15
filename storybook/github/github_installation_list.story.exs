# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.GitHub.GitHubInstallationList do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.GitHubComponents.github_installation_list/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  defp installation(overrides) do
    Map.merge(
      %{
        id: 7,
        account: "acme",
        kind: :organization,
        repository_selection: :all,
        suspended_at: nil,
        repositories: []
      },
      Map.new(overrides)
    )
  end

  defp repository(name) do
    [owner, repo] = String.split(name, "/")
    %{owner: owner, repo: repo}
  end

  def variations do
    [
      %Variation{
        id: :all_repositories,
        description: "An organization installation that covers every repository of the account.",
        attributes: %{installations: [installation([])]}
      },
      %Variation{
        id: :selected_with_repositories,
        description: """
        A user-account installation that covers only the repositories its owner
        selected. The settings link points at the user's own installation page.
        """,
        attributes: %{
          installations: [
            installation(
              id: 8,
              account: "jdoe",
              kind: :user,
              repository_selection: :selected,
              repositories: Enum.map(["jdoe/lib", "jdoe/app", "jdoe/docs"], &repository/1)
            )
          ]
        }
      },
      %Variation{
        id: :selected_without_repositories,
        description: "A selective installation whose repositories are not stored yet.",
        attributes: %{
          installations: [installation(id: 9, account: "bare", repository_selection: :selected)]
        }
      },
      %Variation{
        id: :suspended,
        description: "The account suspended the installation: the amber badge marks it.",
        attributes: %{
          installations: [
            installation(id: 10, account: "frozen", suspended_at: ~U[2026-10-01 12:00:00Z])
          ]
        }
      },
      %Variation{
        id: :several,
        description: "Several installations, one row each.",
        attributes: %{
          installations: [
            installation([]),
            installation(
              id: 8,
              account: "jdoe",
              kind: :user,
              repository_selection: :selected,
              repositories: [repository("jdoe/lib")]
            ),
            installation(id: 10, account: "frozen", suspended_at: ~U[2026-10-01 12:00:00Z])
          ]
        }
      },
      %Variation{
        id: :empty,
        description: "The app is installed on none of the accounts the login reaches.",
        attributes: %{installations: []}
      }
    ]
  end
end
