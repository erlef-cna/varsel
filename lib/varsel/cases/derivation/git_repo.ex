# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.GitRepo do
  @moduledoc """
  `Varsel.Cases.Derivation.GitBackend` implementation on `exgit` — pure
  Elixir, no git binary or libgit2 at runtime.

  Strategy (the equivalent of the cna repo's `refs-containing` cache):

  1. lazy clone — refs only, no objects
  2. one filtered fetch (`tree:0`) wanting **every** ref tip: downloads the
     complete commit graph reachable from tags and branches, no trees, no
     blobs (a plain filtered clone only makes the default branch's history
     resident — tag-only commits would be missing)
  3. build a children adjacency map over the commit graph, BFS the
     descendants of the target commit
  4. a tag contains the commit iff its (peeled) tip *is* the commit or one
     of its descendants

  The graph is held in-memory per repository and rebuilt once it is older
  than the TTL (new release tags must be seen — they decide whether a fix
  counts as released) or when a requested commit is missing (a fix pushed
  after the fetch). Answers are memoized per `{repo, sha}` for the lifetime
  of the cached graph.
  """

  @behaviour Varsel.Cases.Derivation.GitBackend

  use GenServer

  alias Exgit.Object.Commit
  alias Exgit.Object.Tag
  alias Exgit.ObjectStore
  alias Exgit.RefStore

  @ttl_seconds 900

  # Bound the graph walk so a pathological `repo_url` can't tie up derivation
  # (see THREAT_MODEL.md §9): abort once the reachable commit count exceeds
  # this. 250k sits well above any real repo — OTP, one of the largest, is
  # ~65k commits. (A byte cap on the fetch itself isn't usable here: `tree:0`
  # returns only commit objects, and exgit's `max_cache_bytes` evicts exactly
  # those to stay under the cap, which would corrupt the graph.) Overridable
  # via config so tests can drive the cap without a huge fixture.
  @default_max_commits 250_000

  defmodule Graph do
    @moduledoc false
    @enforce_keys [:store, :tags, :children, :fetched_at]
    defstruct [:store, :tags, :children, :fetched_at]
  end

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl Varsel.Cases.Derivation.GitBackend
  def tags_containing(repo_url, sha) do
    GenServer.call(__MODULE__, {:tags_containing, repo_url, sha}, to_timeout(minute: 10))
  end

  @impl GenServer
  def init(_opts) do
    {:ok, %{graphs: %{}, answers: %{}}}
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
    case decode_sha(sha) do
      {:ok, target} ->
        with {:ok, graph, state} <- graph_for(state, repo_url, target) do
          {{:ok, tags_with_descendant(graph, target)}, state}
        end

      :error ->
        {{:error, :invalid_sha}, state}
    end
  end

  # Returns a commit graph that is fresh enough and contains `target`,
  # refetching once when a cached graph is stale or misses the commit.
  defp graph_for(state, repo_url, target) do
    now = System.monotonic_time(:second)

    case Map.fetch(state.graphs, repo_url) do
      {:ok, %Graph{fetched_at: fetched_at} = graph} when now - fetched_at < @ttl_seconds ->
        if Map.has_key?(graph.children, target) or commit?(graph.store, target) do
          {:ok, graph, state}
        else
          fresh_graph(state, repo_url, target)
        end

      _stale_or_missing ->
        fresh_graph(state, repo_url, target)
    end
  end

  defp fresh_graph(state, repo_url, target) do
    case build_graph(repo_url) do
      {:ok, graph} ->
        # A fresh graph invalidates memoized answers for this repo.
        answers =
          state.answers |> Enum.reject(fn {{url, _}, _} -> url == repo_url end) |> Map.new()

        state = %{state | graphs: Map.put(state.graphs, repo_url, graph), answers: answers}

        if Map.has_key?(graph.children, target) or commit?(graph.store, target) do
          {:ok, graph, state}
        else
          {{:error, :commit_not_found}, state}
        end

      {:error, reason} ->
        {{:error, reason}, state}
    end
  end

  # Lazy clone (refs only) + one tree:0 fetch wanting every ref tip, then one
  # BFS over parent edges recording reverse (children) edges.
  defp build_graph(repo_url) do
    with {:clone, {:ok, repo}} <- {:clone, Exgit.clone(repo_url, lazy: true)},
         tags = list_refs(repo, "refs/tags/"),
         tips = ref_tips(tags, list_refs(repo, "refs/heads/")),
         {:fetch, {:ok, store}} <-
           {:fetch, ObjectStore.Promisor.fetch_with_filter(repo.object_store, tips, filter: "tree:0")},
         {:ok, children} <- build_children(store, tips) do
      {:ok,
       %Graph{
         store: store,
         tags: tags,
         children: children,
         fetched_at: System.monotonic_time(:second)
       }}
    else
      {:clone, {:error, reason}} -> {:error, {:clone_failed, reason}}
      {:fetch, {:error, reason}} -> {:error, {:fetch_failed, reason}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp ref_tips(tags, heads) do
    (tags ++ heads) |> Enum.map(&elem(&1, 1)) |> Enum.uniq()
  end

  defp list_refs(repo, prefix) do
    for {name, value} <- RefStore.list(repo.ref_store, prefix),
        {:ok, sha} <- [decode_sha(value)] do
      {String.replace_prefix(name, prefix, ""), sha}
    end
  end

  defp tags_with_descendant(graph, target) do
    descendants = descendants(graph.children, target)

    for {name, tip} <- graph.tags,
        {:ok, commit_sha} <- [peel(graph.store, tip)],
        MapSet.member?(descendants, commit_sha) do
      name
    end
  end

  defp commit?(store, sha), do: match?({:ok, _}, peel(store, sha))

  # Tag refs may point at annotated tag objects; peel to the commit.
  defp peel(store, sha) do
    case ObjectStore.get(store, sha) do
      {:ok, %Commit{}} -> {:ok, sha}
      {:ok, %Tag{object: target}} -> peel(store, target)
      _other -> :error
    end
  end

  defp build_children(store, tips) do
    start = for tip <- tips, {:ok, sha} <- [peel(store, tip)], do: sha

    walk(store, :queue.from_list(start), MapSet.new(start), %{})
  end

  # `seen` accumulates every commit reached, so its size is the running commit
  # count; abort once it exceeds @max_commits rather than walking the whole
  # graph of a pathological repo.
  defp walk(store, queue, seen, children) do
    if MapSet.size(seen) > max_commits() do
      {:error, :too_many_commits}
    else
      case :queue.out(queue) do
        {:empty, _queue} ->
          {:ok, children}

        {{:value, sha}, queue} ->
          {queue, seen, children} = visit(store, sha, queue, seen, children)
          walk(store, queue, seen, children)
      end
    end
  end

  defp visit(store, sha, queue, seen, children) do
    case ObjectStore.get(store, sha) do
      {:ok, %Commit{} = commit} ->
        commit
        |> Commit.parents()
        |> Enum.reduce({queue, seen, children}, &visit_parent(&1, sha, &2))

      _missing ->
        # Shallow boundary or missing object: stop this line.
        {queue, seen, children}
    end
  end

  defp visit_parent(parent, sha, {queue, seen, children}) do
    children = Map.update(children, parent, [sha], &[sha | &1])

    if MapSet.member?(seen, parent) do
      {queue, seen, children}
    else
      {:queue.in(parent, queue), MapSet.put(seen, parent), children}
    end
  end

  defp max_commits do
    Application.get_env(:varsel, :git_max_commits, @default_max_commits)
  end

  # The target itself counts as its own descendant (a tag pointing exactly at
  # the commit contains it).
  defp descendants(children, target) do
    bfs(children, :queue.from_list([target]), MapSet.new([target]))
  end

  defp bfs(children, queue, seen) do
    case :queue.out(queue) do
      {:empty, _queue} ->
        seen

      {{:value, sha}, queue} ->
        {queue, seen} =
          children
          |> Map.get(sha, [])
          |> Enum.reduce({queue, seen}, &enqueue_child/2)

        bfs(children, queue, seen)
    end
  end

  defp enqueue_child(child, {queue, seen}) do
    if MapSet.member?(seen, child) do
      {queue, seen}
    else
      {:queue.in(child, queue), MapSet.put(seen, child)}
    end
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
