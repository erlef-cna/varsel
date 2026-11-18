# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink.Changes.AddCollaborator do
  @moduledoc """
  Makes a person assigned to the case a collaborator on the linked advisory
  at GitHub, as the actor, and leaves what GitHub answered in the changeset
  context for `StoreAdvisory`.

  GitHub replaces the whole collaborator list on each update, and refuses
  the whole update when one login in it does not exist. So the advisory is
  read with the same credential right before the write, and the write sends
  what GitHub then listed plus the new login. A login GitHub lists already
  is not written again.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisory.Refusal
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.Credentials

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.before_transaction(changeset, &add(&1, context))
  end

  defp add(%{valid?: false} = changeset, _context), do: changeset

  defp add(%{data: link} = changeset, context) do
    with {:ok, login} <- login(link, Changeset.get_argument(changeset, :user_id), context),
         {:ok, {owner, repo}} <- repository(link),
         {:ok, advisory} <- write(context.actor, owner, repo, link.ghsa_id, login) do
      Changeset.put_context(changeset, :github_advisory, advisory)
    else
      {:error, message} -> Changeset.add_error(changeset, field: :user_id, message: message)
    end
  end

  defp login(link, user_id, context) do
    case Cases.get_github_collaborator_assignment(
           link.case_id,
           user_id,
           Ash.Context.to_opts(context)
         ) do
      {:ok, %{user: %{github_username: login}}} when is_binary(login) -> {:ok, login}
      _not_assigned -> {:error, "is not assigned to the case with a GitHub account linked"}
    end
  end

  defp repository(%{owner: owner, repo: repo}) when is_binary(owner) and is_binary(repo), do: {:ok, {owner, repo}}

  defp repository(_global_entry), do: {:error, "cannot be added: the advisory is a global database entry"}

  defp write(actor, owner, repo, ghsa_id, login) do
    case Credentials.run(actor, owner, repo, &read_and_add(&1, owner, repo, ghsa_id, login)) do
      {_kind, {:ok, advisory}} ->
        {:ok, advisory}

      {:no_credential, reason} ->
        {:error, Credentials.message(reason)}

      {_kind, answer} ->
        {:error, Refusal.message(answer, "was refused: GitHub shows you no such advisory")}
    end
  end

  defp read_and_add(credential, owner, repo, ghsa_id, login) do
    with {:ok, advisory} <- Advisories.fetch(owner, repo, ghsa_id, token: credential.token) do
      current = for %{"login" => listed} <- List.wrap(advisory["collaborating_users"]), do: listed

      if Enum.any?(current, &(String.downcase(&1) == String.downcase(login))) do
        {:ok, advisory}
      else
        Advisories.update(
          owner,
          repo,
          ghsa_id,
          %{"collaborating_users" => current ++ [login]},
          token: credential.token
        )
      end
    end
  end
end
