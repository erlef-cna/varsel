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

  ## Ownership

  A stub belongs to the test that declared it, so `async: true` tests cannot
  overwrite one another's repo state. Lookups walk `$callers`/`$ancestors`, so
  work a test hands to a Task still sees its owner's stubs.

  This state used to live in one global `:persistent_term` slot, which made
  every stub-using test flaky in proportion to what ran alongside it: a
  concurrent `stub_tags/1` replaced the running test's tags wholesale, and its
  `on_exit` then erased them regardless of which test had written them.
  """

  @behaviour Varsel.Cases.Derivation.GitBackend

  alias Varsel.Cases.Derivation.GitBackend

  @tags_key {__MODULE__, :tags}
  @universe_key {__MODULE__, :universe}
  @refreshed_key {__MODULE__, :refreshed}

  @doc "Declares, per `{repo, sha}`, the tags whose commit contains that sha."
  @spec stub_tags(%{{String.t(), String.t()} => [String.t()]}) :: :ok
  def stub_tags(tags), do: put(@tags_key, tags)

  @doc "Extra tags to include in `all_tags/1` for a repo (unaffected-everywhere tags)."
  @spec stub_all_tags(%{String.t() => [String.t()]}) :: :ok
  def stub_all_tags(universe), do: put(@universe_key, universe)

  @impl GitBackend
  def tags_containing(repo_url, sha) do
    case Map.fetch(get(@tags_key), {repo_url, sha}) do
      {:ok, tags} -> {:ok, tags}
      :error -> {:error, :commit_not_found}
    end
  end

  @impl GitBackend
  def all_tags(repo_url) do
    from_commits =
      for {{repo, _sha}, tags} <- get(@tags_key),
          repo == repo_url,
          tag <- tags,
          do: tag

    extra = Map.get(get(@universe_key), repo_url, [])

    {:ok, Enum.uniq(from_commits ++ extra)}
  end

  # Recorded in the calling process's dictionary, so a test that runs the
  # action in its own process reads the record back with `refreshed_repos/0`.
  @impl GitBackend
  def refresh(repo_url) do
    Process.put(@refreshed_key, refreshed_repos() ++ [repo_url])
    :ok
  end

  @doc "Repo URLs `refresh/1` was called with, oldest first."
  @spec refreshed_repos() :: [String.t()]
  def refreshed_repos, do: get(@refreshed_key, owners(), [])

  ## ----------------------------------------------------------------- storage

  # ExUnit already gives each test its own process, so its dictionary is the
  # isolation — and it dies with the test, which is why nothing has to clean up.
  defp put(key, value) do
    Process.put(key, value)
    :ok
  end

  # This process if it declared the stub, else the nearest caller or ancestor
  # that did. Presence decides, not truthiness, so a deliberately empty stub
  # answers for its owner instead of falling through to an ancestor's.
  defp get(key), do: get(key, owners(), %{})

  defp get(_key, [], default), do: default

  defp get(key, [pid | rest], default) do
    case dictionary(pid) do
      %{^key => value} -> value
      _undeclared -> get(key, rest, default)
    end
  end

  defp owners do
    callers = Process.get(:"$callers", [])
    ancestors = Enum.filter(Process.get(:"$ancestors", []), &is_pid/1)

    [self() | callers ++ ancestors]
  end

  defp dictionary(pid) when pid == self(), do: Map.new(Process.get())

  defp dictionary(pid) do
    case Process.info(pid, :dictionary) do
      {:dictionary, entries} -> Map.new(entries)
      nil -> %{}
    end
  end
end
