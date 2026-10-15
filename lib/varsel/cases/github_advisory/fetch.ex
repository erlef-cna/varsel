# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Fetch do
  @moduledoc """
  Reads an advisory from GitHub for an action, as the person asking.

  A repository advisory is read with the credential
  `Varsel.GitHub.Credentials` gives the actor for its repository, so a draft
  answers exactly when GitHub shows it to that credential. A global
  database entry is read with the home organization's installation token.
  Failures come back as the sentence an action puts on its `advisory_url`
  field.
  """

  alias Varsel.Accounts.User
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.Credentials

  @type result :: {:ok, map()} | {:error, String.t()}

  @doc "The advisory a pasted URL or GHSA id names."
  @spec fetch(term(), User.t() | nil) :: result()
  def fetch(url, actor) when is_binary(url) do
    case Advisories.parse(url) do
      {:ok, ref} -> fetch_ref(ref, actor)
      :error -> {:error, "is not a GitHub advisory URL or GHSA id"}
    end
  end

  def fetch(_url, _actor), do: {:error, "is not a GitHub advisory URL or GHSA id"}

  @doc "The advisory a parsed reference names: on its repository, or the global database entry."
  @spec fetch_ref(Advisories.ref(), User.t() | nil) :: result()
  def fetch_ref(%{owner: owner, repo: repo, ghsa_id: ghsa_id}, actor) when is_binary(owner) and is_binary(repo) do
    case Credentials.run(
           actor,
           owner,
           repo,
           &Advisories.fetch(owner, repo, ghsa_id, token: &1.token)
         ) do
      {:no_credential, reason} -> {:error, Credentials.message(reason)}
      {_kind, answer} -> fetched(answer)
    end
  end

  def fetch_ref(%{ghsa_id: ghsa_id}, _actor) do
    case Credentials.public_read() do
      {:ok, credential} ->
        ghsa_id |> Advisories.fetch_global(token: credential.token) |> fetched()

      {:error, reason} ->
        {:error, Credentials.message(reason)}
    end
  end

  defp fetched({:ok, advisory}), do: {:ok, advisory}
  defp fetched(:not_found), do: {:error, "names no advisory you can see on GitHub"}
  defp fetched({:error, _reason}), do: {:error, "could not be fetched from GitHub"}
end
