# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.GitRepo do
  @moduledoc """
  `Varsel.Cases.Derivation.GitBackend` implementation on `exgit` — pure
  Elixir, no git binary or libgit2 at runtime.

  Repositories are cloned commits-only (`filter: {:tree, 0}`, the equivalent
  of the cna repo's `refs-containing --filter=tree:0` cache) and held
  in-memory by this GenServer. A cached repository is re-cloned once it is
  older than the TTL (new release tags must be seen — they decide whether a
  fix counts as released) or when a requested commit is missing (a fix pushed
  after the clone).

  "Tag contains commit" is answered with `Exgit.Walk.merge_base/2`: a tag's
  commit contains `sha` iff their merge base *is* `sha`. Results are memoized
  per `{repo, sha}` for the lifetime of the cached clone.
  """

  @behaviour Varsel.Cases.Derivation.GitBackend

  use GenServer

  alias Exgit.Object.Commit
  alias Exgit.Object.Tag
  alias Exgit.ObjectStore
  alias Exgit.RefStore
  alias Exgit.Walk

  @ttl_seconds 900

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl Varsel.Cases.Derivation.GitBackend
  def tags_containing(repo_url, sha) do
    GenServer.call(__MODULE__, {:tags_containing, repo_url, sha}, to_timeout(minute: 10))
  end

  @impl GenServer
  def init(_opts) do
    {:ok, %{repos: %{}, answers: %{}}}
  end

  @impl GenServer
  def handle_call({:tags_containing, repo_url, sha}, _from, state) do
    case Map.fetch(state.answers, {repo_url, sha}) do
      {:ok, answer} ->
        {:reply, answer, state}

      :error ->
        {answer, state} = compute(state, repo_url, sha)
        {:reply, answer, put_in(state.answers[{repo_url, sha}], answer)}
    end
  end

  defp compute(state, repo_url, sha) do
    with {:ok, repo, state} <- repo_for(state, repo_url, sha) do
      {walk_tags(repo, sha), state}
    end
  end

  # Returns a repo that is fresh enough and contains `sha`, re-cloning once
  # if a cached clone is stale or misses the commit.
  defp repo_for(state, repo_url, sha) do
    now = System.monotonic_time(:second)

    case Map.fetch(state.repos, repo_url) do
      {:ok, {repo, cloned_at}} when now - cloned_at < @ttl_seconds ->
        if commit_present?(repo, sha) do
          {:ok, repo, state}
        else
          fresh_clone(state, repo_url, sha)
        end

      _stale_or_missing ->
        fresh_clone(state, repo_url, sha)
    end
  end

  defp fresh_clone(state, repo_url, sha) do
    case Exgit.clone(repo_url, filter: {:tree, 0}) do
      {:ok, repo} ->
        now = System.monotonic_time(:second)

        # A fresh clone invalidates memoized answers for this repo.
        answers =
          state.answers |> Enum.reject(fn {{url, _}, _} -> url == repo_url end) |> Map.new()

        state = %{state | repos: Map.put(state.repos, repo_url, {repo, now}), answers: answers}

        if commit_present?(repo, sha) do
          {:ok, repo, state}
        else
          {{:error, :commit_not_found}, state}
        end

      {:error, reason} ->
        {{:error, {:clone_failed, reason}}, state}
    end
  end

  defp commit_present?(repo, sha) do
    case decode_sha(sha) do
      {:ok, bin} -> match?({:ok, %Commit{}}, ObjectStore.get(repo.object_store, bin))
      :error -> false
    end
  end

  defp walk_tags(repo, sha) do
    {:ok, target} = decode_sha(sha)

    tags =
      repo.ref_store
      |> RefStore.list("refs/tags/")
      |> Enum.flat_map(fn {name, value} ->
        case peel(repo, value) do
          {:ok, commit_sha} -> [{String.replace_prefix(name, "refs/tags/", ""), commit_sha}]
          :error -> []
        end
      end)
      |> Enum.filter(fn {_name, commit_sha} -> contains?(repo, commit_sha, target) end)
      |> Enum.map(&elem(&1, 0))

    {:ok, tags}
  end

  # Tag refs may point at annotated tag objects; peel to the commit.
  defp peel(repo, value) do
    with {:ok, bin} <- decode_sha(value) do
      case ObjectStore.get(repo.object_store, bin) do
        {:ok, %Commit{}} -> {:ok, bin}
        {:ok, %Tag{object: target}} -> peel(repo, target)
        _other -> :error
      end
    end
  end

  defp contains?(_repo, commit_sha, target) when commit_sha == target, do: true

  defp contains?(repo, commit_sha, target) do
    match?({:ok, ^target}, Walk.merge_base(repo, [commit_sha, target]))
  end

  # Accepts 40-char hex or raw 20-byte binary SHAs.
  defp decode_sha(<<_::binary-size(20)>> = bin), do: {:ok, bin}

  defp decode_sha(hex) when byte_size(hex) == 40 do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> {:ok, bin}
      :error -> :error
    end
  end

  defp decode_sha(_other), do: :error
end
