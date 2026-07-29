# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.GitRepo.Server do
  @moduledoc """
  One repository's commit graph, held by one process.

  Started on demand by `Varsel.Cases.Derivation.GitRepo` and registered under
  the repo URL. Builds the graph once — lazy clone (refs only), one `tree:0`
  fetch wanting every ref tip, children adjacency map — then serves memoized
  answers from process state. The graph expires `@ttl` after the clone/fetch
  that produced it — calls do not extend the deadline. Past the deadline the
  server unregisters and stops, so the graph and the memoized answers expire
  together; the next call starts a fresh server and rescans. A failed build
  answers the callers already queued and stops at the first idle moment —
  errors are never held for the TTL.

  `:refresh` brings the graph up to date in place with an incremental fetch
  (new refs and commits only, see `refresh_graph/1`) and drops the memoized
  answers; if the incremental path fails, the server stops instead — the
  next call rescans from scratch.
  """

  use GenServer, restart: :temporary

  alias Exgit.Object.Commit
  alias Exgit.Object.Tag
  alias Exgit.ObjectStore
  alias Exgit.RefStore
  alias Varsel.Cases.Derivation.PinnedTransport

  @registry Varsel.Cases.Derivation.GitRepo.Registry

  @ttl to_timeout(second: 900)

  # How long a failed build keeps answering before the server stops. Not 0:
  # a build that fails instantly (e.g. a refused address) would otherwise
  # stop before the very caller that started the server lands its call,
  # which the caller sees as :noproc. Long enough for in-flight callers,
  # short enough that a transient error is never pinned.
  @error_grace to_timeout(millisecond: 250)

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
    # `repo`/`remote`/`tips`/`seen` exist for incremental refresh: the
    # repository and transport to fetch into, the ref tips of the last scan
    # (the `haves` frontier), and every commit already walked (where the
    # extension walk stops).
    @enforce_keys [:repo, :remote, :store, :tags, :children, :tips, :seen]
    defstruct [:repo, :remote, :store, :tags, :children, :tips, :seen]
  end

  def start_link(repo_url) do
    GenServer.start_link(__MODULE__, repo_url, name: {:via, Registry, {@registry, repo_url}})
  end

  @impl GenServer
  def init(repo_url) do
    # The clone must not run here: DynamicSupervisor.start_child blocks the
    # supervisor until init returns, which would head-of-line-block every
    # other repo's first call. The continue runs before any queued call.
    {:ok, %{repo_url: repo_url, graph: nil, error: nil, answers: %{}, deadline: nil}, {:continue, :build}}
  end

  @impl GenServer
  def handle_continue(:build, state) do
    case build_commit_graph(state.repo_url) do
      {:ok, graph} ->
        state = renew(%{state | graph: graph})
        {:noreply, state, remaining(state)}

      {:error, reason} ->
        {:noreply, %{state | error: reason}, @error_grace}
    end
  end

  @impl GenServer
  def handle_call(_request, _from, %{error: reason} = state) when reason != nil do
    {:reply, {:error, reason}, state, @error_grace}
  end

  @impl GenServer
  def handle_call(:refresh, _from, state) do
    case refresh_graph(state.graph) do
      {:ok, graph} ->
        state = renew(%{state | graph: graph, answers: %{}})
        {:reply, :ok, state, remaining(state)}

      {:error, _reason} ->
        # Fall back to the restart path: drop everything so the next call
        # rescans from scratch instead of serving a graph of unknown state.
        Registry.unregister(@registry, state.repo_url)
        {:stop, :normal, :ok, state}
    end
  end

  @impl GenServer
  def handle_call({:tags_containing, sha}, _from, state) do
    case Map.fetch(state.answers, sha) do
      {:ok, answer} ->
        {:reply, answer, state, remaining(state)}

      :error ->
        {answer, state} = compute(state, sha)
        {:reply, answer, memoize(state, sha, answer), remaining(state)}
    end
  end

  @impl GenServer
  def handle_call(:all_tags, _from, state) do
    {:reply, {:ok, Enum.map(state.graph.tags, &elem(&1, 0))}, state, remaining(state)}
  end

  @impl GenServer
  def handle_info(:timeout, state) do
    Registry.unregister(@registry, state.repo_url)
    {:stop, :normal, state}
  end

  # The deadline is anchored to the clone/fetch that produced the graph;
  # calls never extend it — each reply carries the remaining time, so the
  # timeout fires @ttl after the scan regardless of traffic.
  defp renew(state), do: %{state | deadline: System.monotonic_time(:millisecond) + @ttl}

  defp remaining(%{deadline: deadline}) do
    max(deadline - System.monotonic_time(:millisecond), 0)
  end

  # A failed refetch is transient — memoizing it would pin the error for the
  # server's life. Definitive answers (including a commit genuinely absent
  # after a refetch) are kept until the server expires.
  defp memoize(state, sha, answer) do
    case answer do
      {:error, reason} when reason not in [:commit_not_found, :invalid_sha] -> state
      _definitive -> put_in(state.answers[sha], answer)
    end
  end

  defp compute(state, sha) do
    case decode_sha(sha) do
      {:ok, target} ->
        case graph_containing(state, target) do
          {:ok, graph, state} -> {{:ok, tags_with_descendant(graph, target)}, state}
          {:error, reason, state} -> {{:error, reason}, state}
        end

      :error ->
        {{:error, :invalid_sha}, state}
    end
  end

  # The graph, refetched once when the commit is missing (a fix pushed after
  # our fetch). A failed refetch keeps the old graph and keeps serving.
  defp graph_containing(%{graph: graph} = state, target) do
    if contains?(graph, target) do
      {:ok, graph, state}
    else
      refetch(state, target)
    end
  end

  defp refetch(state, target) do
    case build_commit_graph(state.repo_url) do
      {:ok, fresh} ->
        # A fresh graph invalidates the memoized answers and renews the TTL.
        state = renew(%{state | graph: fresh, answers: %{}})

        if contains?(fresh, target),
          do: {:ok, fresh, state},
          else: {:error, :commit_not_found, state}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp contains?(graph, target) do
    Map.has_key?(graph.children, target) or commit?(graph.store, target)
  end

  # Lazy clone (refs only) + one tree:0 fetch wanting every ref tip, then one
  # BFS over parent edges recording reverse (children) edges. The clone wrote
  # branch tips to refs/heads/, and the tips must be listed up front — the
  # promisor fetch takes them as its wants.
  defp build_commit_graph(repo_url) do
    with {:pin, {:ok, remote}} <- {:pin, remote(repo_url)},
         {:clone, {:ok, repo}} <- {:clone, Exgit.clone(remote, lazy: true)},
         tips = ref_tips(list_refs(repo, "refs/tags/"), list_refs(repo, "refs/heads/")),
         {:fetch, {:ok, store}} <-
           {:fetch, ObjectStore.Promisor.fetch_with_filter(repo.object_store, tips, filter: "tree:0")} do
      assemble(%{repo | object_store: store}, remote, "refs/heads/", MapSet.new(), %{})
    else
      {:pin, {:error, reason}} -> {:error, {:clone_failed, reason}}
      {:clone, {:error, reason}} -> {:error, {:clone_failed, reason}}
      {:fetch, {:error, reason}} -> {:error, {:fetch_failed, reason}}
    end
  end

  # Anything dialled over the network is pinned to the address it was checked
  # at (see `PinnedTransport`); a URL with no host to resolve — `file://`, the
  # fixture the derivation tests clone — has nothing to pin and goes to exgit
  # as-is. Which schemes may be *stored* is the attribute's constraint.
  defp remote(repo_url) do
    case URI.new(repo_url) do
      {:ok, %URI{scheme: scheme}} when scheme in ["https", "http"] ->
        PinnedTransport.build(repo_url)

      _nothing_to_pin ->
        {:ok, repo_url}
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

  # Incremental refresh: one ls-refs plus a commits-only delta pack —
  # `filter:` and `haves:` pass through `Exgit.fetch/3` into the transport —
  # then the children map is extended from the tips we have not walked yet.
  # `Exgit.fetch/3` writes remote-tracking refs but never prunes, so a tag
  # deleted upstream lingers until the server expires; fresh branch tips land
  # under refs/remotes/origin/ while refs/heads/ stays at clone time.
  defp refresh_graph(%Graph{} = graph) do
    haves = peeled_tips(graph.store, graph.tips)

    with {:ok, repo} <- Exgit.fetch(graph.repo, graph.remote, filter: "tree:0", haves: haves) do
      assemble(repo, graph.remote, "refs/remotes/origin/", graph.seen, graph.children)
    end
  end

  # Lists refs, walks from the peeled tips not yet in `base_seen`, and
  # assembles the Graph. The initial scan starts from an empty base and reads
  # branch tips where the clone wrote them (refs/heads/); refresh extends the
  # previous graph and reads them where `Exgit.fetch` wrote them
  # (refs/remotes/origin/).
  defp assemble(repo, remote, heads_prefix, base_seen, base_children) do
    store = repo.object_store
    tags = list_refs(repo, "refs/tags/")
    tips = ref_tips(tags, list_refs(repo, heads_prefix))
    start = Enum.reject(peeled_tips(store, tips), &MapSet.member?(base_seen, &1))
    seen = MapSet.union(base_seen, MapSet.new(start))

    with {:ok, children, seen} <- walk(store, :queue.from_list(start), seen, base_children) do
      {:ok,
       %Graph{
         repo: repo,
         remote: remote,
         store: store,
         tags: tags,
         children: children,
         tips: tips,
         seen: seen
       }}
    end
  end

  defp peeled_tips(store, tips) do
    for_result = for(tip <- tips, {:ok, sha} <- [peel(store, tip)], do: sha)
    Enum.uniq(for_result)
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
          {:ok, children, seen}

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
