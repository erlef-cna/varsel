# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GitHubComponents do
  @moduledoc """
  Components that render what the GitHub App can reach for a person.
  """

  use Phoenix.Component

  import VarselWeb.CoreComponents, only: [empty_state: 1, icon: 1, mono_chip: 1]

  @doc """
  Renders the installations of the GitHub App that a person's GitHub login
  reaches. Each row names the account, says which of its repositories the
  installation covers, and links to the installation's settings on GitHub.

  Each installation needs `:id`, `:account`, `:kind`,
  `:repository_selection`, `:suspended_at` and `:repositories`, a list of
  maps with `:owner` and `:repo`.
  """
  attr :installations, :list, required: true

  def github_installation_list(assigns) do
    ~H"""
    <.empty_state :if={@installations == []} class="py-4">
      The app is installed on none of the accounts your GitHub login can reach.
    </.empty_state>

    <ul :if={@installations != []} class="divide-y divide-base-300">
      <li
        :for={installation <- @installations}
        id={"github-installation-#{installation.id}"}
        class="py-2 space-y-1"
      >
        <div class="flex flex-wrap items-center gap-2">
          <span class="font-medium">{installation.account}</span>
          <span class="badge badge-ghost badge-xs">{kind_label(installation.kind)}</span>
          <span :if={installation.suspended_at} class="badge badge-warning badge-xs">suspended</span>
          <.link
            href={settings_url(installation)}
            target="_blank"
            rel="noopener"
            class="link link-hover text-primary text-xs ml-auto inline-flex items-center gap-1"
          >
            Settings on GitHub <.icon name="hero-arrow-top-right-on-square" class="size-3" />
          </.link>
        </div>
        <.coverage installation={installation} />
      </li>
    </ul>
    """
  end

  attr :installation, :map, required: true

  defp coverage(%{installation: %{repository_selection: :all}} = assigns) do
    ~H"""
    <p class="text-sm text-base-content/70">All repositories</p>
    """
  end

  defp coverage(%{installation: %{repositories: []}} = assigns) do
    ~H"""
    <p class="text-sm text-base-content/60">No repositories yet</p>
    """
  end

  defp coverage(assigns) do
    ~H"""
    <div class="flex flex-wrap gap-1">
      <.mono_chip :for={repository <- sorted(@installation.repositories)} size={:small}>
        {repository.owner}/{repository.repo}
      </.mono_chip>
    </div>
    """
  end

  defp sorted(repositories), do: Enum.sort_by(repositories, &String.downcase("#{&1.owner}/#{&1.repo}"))

  defp kind_label(:organization), do: "organization"
  defp kind_label(:user), do: "user"

  defp settings_url(%{kind: :organization, account: account, id: id}),
    do: "https://github.com/organizations/#{account}/settings/installations/#{id}"

  defp settings_url(%{kind: :user, id: id}), do: "https://github.com/settings/installations/#{id}"
end
