# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment.Changes.ResolveGitHubAuthor do
  @moduledoc """
  Names the account whose GitHub identity holds the login a comment was
  written by.

  A comment keeps the login whether or not an account holds it, so the login
  stays the record of who wrote it on GitHub. The account is what lets the
  stream show a person the case already knows.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Resource.Change
  alias Varsel.Accounts.UserIdentity
  alias Varsel.Service

  require Ash.Query

  @impl Change
  def change(changeset, _opts, _context) do
    case Changeset.get_attribute(changeset, :github_author_login) do
      login when is_binary(login) ->
        Changeset.force_change_attribute(changeset, :author_id, author_id(login))

      nil ->
        changeset
    end
  end

  defp author_id(login) do
    UserIdentity
    |> Ash.Query.filter(strategy == "github" and username == ^login)
    |> Ash.Query.select([:user_id])
    |> Ash.read_one!(actor: Service.identity_claim())
    |> case do
      %{user_id: user_id} -> user_id
      nil -> nil
    end
  end
end
