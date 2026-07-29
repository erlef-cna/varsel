# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.GitBackend do
  @moduledoc """
  The single question derivation asks a git repository: which release tags
  contain a given commit?

  The default implementation is `Varsel.Cases.Derivation.GitRepo` (pure-Elixir
  git via `exgit`); tests configure a stub via
  `config :varsel, :git_backend, MyStub`.
  """

  @doc """
  All tag names (bare, without `refs/tags/`) whose tagged commit has `sha`
  as an ancestor (inclusive). `{:error, :commit_not_found}` when the commit
  does not exist in the repository.
  """
  @callback tags_containing(repo_url :: String.t(), sha :: String.t()) ::
              {:ok, [String.t()]} | {:error, term()}

  @doc """
  Every release tag name (bare, without `refs/tags/`) in the repository — the
  version universe `Varsel.Cases.Reachability` sorts and labels. Includes tags
  that contain neither the intro nor a fix (an unaffected tag never surfaces
  through `tags_containing/2` alone).
  """
  @callback all_tags(repo_url :: String.t()) :: {:ok, [String.t()]} | {:error, term()}

  @doc """
  Brings any cached state for `repo_url` up to date with the remote, so
  refs and commits pushed since the last scan become visible without
  waiting for expiry. A backend without cached state does nothing.
  """
  @callback refresh(repo_url :: String.t()) :: :ok

  @spec impl() :: module()
  def impl, do: Application.get_env(:varsel, :git_backend, Varsel.Cases.Derivation.GitRepo)

  @spec tags_containing(String.t(), String.t()) :: {:ok, [String.t()]} | {:error, term()}
  def tags_containing(repo_url, sha), do: impl().tags_containing(repo_url, sha)

  @spec all_tags(String.t()) :: {:ok, [String.t()]} | {:error, term()}
  def all_tags(repo_url), do: impl().all_tags(repo_url)

  @spec refresh(String.t()) :: :ok
  def refresh(repo_url), do: impl().refresh(repo_url)
end
