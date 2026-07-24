# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.StubGitBackend do
  @moduledoc """
  Test double for `Varsel.Cases.Derivation.GitBackend`.

  Tests declare the repo state with `stub_tags/1` — for each commit, the tags
  whose commit contains it:

      StubGitBackend.stub_tags(%{
        {"https://github.com/acme/pkg", "aaaa..."} => ["v1.0.0", "v2.0.0"],
        {"https://github.com/acme/pkg", "bbbb..."} => []   # commit known, unreleased
      })

  Unknown `{repo, sha}` pairs answer `{:error, :commit_not_found}`. `all_tags/1`
  returns, per repo, the union of every tag mentioned across its commits — plus
  any extra tags declared with `stub_all_tags/1` for versions that contain
  neither the intro nor a fix (and so appear in no commit's list).
  """

  @behaviour Varsel.Cases.Derivation.GitBackend

  alias Varsel.Cases.Derivation.GitBackend

  @key {__MODULE__, :tags}
  @universe_key {__MODULE__, :universe}

  @spec stub_tags(%{{String.t(), String.t()} => [String.t()]}) :: :ok
  def stub_tags(tags) do
    :persistent_term.put(@key, tags)
    ExUnit.Callbacks.on_exit(fn -> :persistent_term.erase(@key) end)
    :ok
  end

  @doc "Extra tags to include in `all_tags/1` for a repo (unaffected-everywhere tags)."
  @spec stub_all_tags(%{String.t() => [String.t()]}) :: :ok
  def stub_all_tags(universe) do
    :persistent_term.put(@universe_key, universe)
    ExUnit.Callbacks.on_exit(fn -> :persistent_term.erase(@universe_key) end)
    :ok
  end

  @impl GitBackend
  def tags_containing(repo_url, sha) do
    case Map.fetch(:persistent_term.get(@key, %{}), {repo_url, sha}) do
      {:ok, tags} -> {:ok, tags}
      :error -> {:error, :commit_not_found}
    end
  end

  @impl GitBackend
  def all_tags(repo_url) do
    from_commits =
      for {{repo, _sha}, tags} <- :persistent_term.get(@key, %{}),
          repo == repo_url,
          tag <- tags,
          do: tag

    extra = Map.get(:persistent_term.get(@universe_key, %{}), repo_url, [])

    {:ok, Enum.uniq(from_commits ++ extra)}
  end
end
