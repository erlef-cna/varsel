# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.GitRepoTest do
  @moduledoc """
  Exercises the real exgit-backed GitBackend against a local fixture
  repository over the file:// transport — the full lazy-clone → tip fetch →
  children-graph → descendant-BFS pipeline, no network.

  Regression: a tag pointing *exactly* at the commit (v0.8.0-style, the
  peeled target) must count as containing it; tag-only history off the
  default branch must be reachable.
  """

  use ExUnit.Case, async: false

  alias Exgit.Object.Commit
  alias Exgit.Object.Tag
  alias Exgit.Object.Tree
  alias Exgit.ObjectStore
  alias Exgit.RefStore
  alias Varsel.Cases.Derivation.GitRepo

  @person "Test <test@example.com> 1700000000 +0000"

  @registry Varsel.Cases.Derivation.GitRepo.Registry

  # Commit graph (only c3/c4 are on main; everything else is tag/branch-only):
  #
  #   c1 ── c2 ── c3 ── c4      tags: v1.0.0 (annotated -> c2), v2.0.0 -> c3
  #     └── b1                  tag:  v1.5.0 -> b1 (side branch); c4 untagged
  setup do
    dir = Path.join(System.tmp_dir!(), "git_repo_fixture_#{System.unique_integer([:positive])}")
    {:ok, repo} = Exgit.init(path: dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    store = repo.object_store
    {:ok, tree_sha, store} = ObjectStore.put(store, Tree.new([]))

    commit = fn store, parents, message ->
      {:ok, sha, store} =
        ObjectStore.put(
          store,
          Commit.new(
            tree: tree_sha,
            parents: parents,
            author: @person,
            committer: @person,
            message: message
          )
        )

      {sha, store}
    end

    {c1, store} = commit.(store, [], "c1")
    {c2, store} = commit.(store, [c1], "c2")
    {c3, store} = commit.(store, [c2], "c3")
    {c4, store} = commit.(store, [c3], "c4")
    {b1, store} = commit.(store, [c1], "b1")

    {:ok, annotated, store} =
      ObjectStore.put(
        store,
        Tag.new(object: c2, tag: "v1.0.0", tagger: @person, message: "v1.0.0")
      )

    ref_store = repo.ref_store
    {:ok, ref_store} = RefStore.write(ref_store, "refs/heads/main", c4, [])
    {:ok, ref_store} = RefStore.write(ref_store, "refs/heads/backport", b1, [])
    {:ok, ref_store} = RefStore.write(ref_store, "refs/tags/v1.0.0", annotated, [])
    {:ok, ref_store} = RefStore.write(ref_store, "refs/tags/v1.5.0", b1, [])
    {:ok, ref_store} = RefStore.write(ref_store, "refs/tags/v2.0.0", c3, [])

    %{
      url: "file://" <> dir,
      c1: hex(c1),
      c2: hex(c2),
      b1: hex(b1),
      c4: hex(c4),
      c4_raw: c4,
      ref_store: ref_store,
      store: store,
      tree_sha: tree_sha
    }
  end

  defp hex(sha), do: Base.encode16(sha, case: :lower)

  test "a tag pointing exactly at the commit (via an annotated tag) contains it", %{
    url: url,
    c2: c2
  } do
    assert {:ok, tags} = GitRepo.tags_containing(url, c2)
    assert Enum.sort(tags) == ["v1.0.0", "v2.0.0"]
  end

  test "the root commit is contained in every tag, across branches", %{url: url, c1: c1} do
    assert {:ok, tags} = GitRepo.tags_containing(url, c1)
    assert Enum.sort(tags) == ["v1.0.0", "v1.5.0", "v2.0.0"]
  end

  test "a commit only on a side branch is found through its tag", %{url: url, b1: b1} do
    assert {:ok, tags} = GitRepo.tags_containing(url, b1)
    assert tags == ["v1.5.0"]
  end

  test "an unknown commit reports commit_not_found", %{url: url} do
    assert {:error, :commit_not_found} = GitRepo.tags_containing(url, String.duplicate("f", 40))
  end

  # `NormalizeRepoUrl` lowercases the scheme on write, so a mixed-case value
  # should no longer reach here — but rows stored before that existed still
  # can, and the dispatch is the control that must not be spelling-sensitive.
  # A prefix match sent these to exgit unpinned: validated at save time,
  # never re-checked at connect time.
  test "a mixed-case https scheme is pinned, not handed to exgit unpinned", %{c2: c2} do
    # Loopback: reaching the pinning check at all means it is refused. A
    # prefix match would skip pinning and let exgit dial it.
    assert {:error, {:clone_failed, :private_address}} =
             GitRepo.tags_containing("HTTPS://127.0.0.1/acme/lib", c2)
  end

  # The `repo_url` constraint rejects plaintext, so no stored row reaches this
  # — but the
  # dispatch pins it rather than passing it through, so widening the
  # validation cannot silently produce an unpinned clone.
  test "http is pinned too, not handed to exgit unpinned", %{url: url, c2: c2} do
    assert {:error, {:clone_failed, :private_address}} =
             GitRepo.tags_containing("http://127.0.0.1/acme/lib", c2)

    # A failed repository must not poison queries for other repositories.
    assert {:ok, tags} = GitRepo.tags_containing(url, c2)
    assert Enum.sort(tags) == ["v1.0.0", "v2.0.0"]
  end

  test "aborts when the commit graph exceeds the configured cap", %{url: url, c2: c2} do
    # The fixture has 4 commits; a cap of 2 trips the graph-walk bound.
    prev = Application.get_env(:varsel, :git_max_commits)
    Application.put_env(:varsel, :git_max_commits, 2)
    on_exit(fn -> restore_env(:git_max_commits, prev) end)

    assert {:error, :too_many_commits} = GitRepo.tags_containing(url, c2)
  end

  defp restore_env(key, nil), do: Application.delete_env(:varsel, key)
  defp restore_env(key, value), do: Application.put_env(:varsel, key, value)

  # INT-004 regression: commits and tags pushed after the first scan must
  # become visible on BOTH query paths at once — memoized answers may never
  # outlive the graph they were computed from. The refresh is incremental:
  # the same server extends its graph in place.
  test "refresh picks up commits and tags pushed after the first scan", %{
    url: url,
    c4: c4,
    c4_raw: c4_raw,
    ref_store: ref_store,
    store: store,
    tree_sha: tree_sha
  } do
    assert {:ok, []} = GitRepo.tags_containing(url, c4)
    assert {:ok, tags} = GitRepo.all_tags(url)
    refute "v3.0.0" in tags
    [{pid, _value}] = Registry.lookup(@registry, url)

    # Pushed after the scan: c5 on top of c4, plus release tags for both.
    {:ok, c5, _store} =
      ObjectStore.put(
        store,
        Commit.new(
          tree: tree_sha,
          parents: [c4_raw],
          author: @person,
          committer: @person,
          message: "c5"
        )
      )

    {:ok, ref_store} = RefStore.write(ref_store, "refs/tags/v3.0.0", c4_raw, [])
    {:ok, _ref_store} = RefStore.write(ref_store, "refs/tags/v3.1.0", c5, [])

    # Still the memoized answer — the push alone is not visible yet.
    assert {:ok, []} = GitRepo.tags_containing(url, c4)

    assert :ok = GitRepo.refresh(url)

    # Same server, graph extended in place — not a restart.
    assert [{^pid, _value}] = Registry.lookup(@registry, url)

    # v3.1.0 contains c4 through the NEW edge c4 -> c5.
    assert {:ok, tags} = GitRepo.tags_containing(url, c4)
    assert Enum.sort(tags) == ["v3.0.0", "v3.1.0"]
    assert {:ok, ["v3.1.0"]} = GitRepo.tags_containing(url, hex(c5))
    assert {:ok, tags} = GitRepo.all_tags(url)
    assert "v3.0.0" in tags
    assert "v3.1.0" in tags
  end

  test "a failed refresh falls back to a restart", %{url: url, c2: c2} do
    assert {:ok, _tags} = GitRepo.tags_containing(url, c2)
    [{pid, _value}] = Registry.lookup(@registry, url)

    # Shrink the cap below the already-walked commit count: the refresh's
    # extension walk fails immediately, so the server must drop out and the
    # next call must rescan fresh.
    prev = Application.get_env(:varsel, :git_max_commits)
    Application.put_env(:varsel, :git_max_commits, 2)
    on_exit(fn -> restore_env(:git_max_commits, prev) end)

    ref = Process.monitor(pid)
    assert :ok = GitRepo.refresh(url)
    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000

    restore_env(:git_max_commits, prev)

    assert {:ok, tags} = GitRepo.tags_containing(url, c2)
    assert Enum.sort(tags) == ["v1.0.0", "v2.0.0"]
  end

  test "refresh of a repository with no cached state is a no-op" do
    url = "file:///absent_#{System.unique_integer([:positive])}"

    assert :ok = GitRepo.refresh(url)
    assert [] = Registry.lookup(@registry, url)
  end

  # The file transport treats a missing path as an empty repository, so the
  # deterministic way to fail a build is the commit cap; the error path is
  # the same one a failed clone takes.
  test "a failed build is not pinned: the next call rescans and succeeds", %{url: url, c2: c2} do
    prev = Application.get_env(:varsel, :git_max_commits)
    Application.put_env(:varsel, :git_max_commits, 2)
    on_exit(fn -> restore_env(:git_max_commits, prev) end)

    assert {:error, :too_many_commits} = GitRepo.tags_containing(url, c2)

    restore_env(:git_max_commits, prev)
    await_server_exit(url)

    assert {:ok, tags} = GitRepo.tags_containing(url, c2)
    assert Enum.sort(tags) == ["v1.0.0", "v2.0.0"]
  end

  # The TTL expiry itself (not just refresh) must drop stale answers: the
  # server unregisters and stops, and the next call rescans. This is the
  # primary INT-004 mechanism — a new release tag becomes visible on both
  # query paths after expiry, on a fresh server.
  test "TTL expiry drops stale answers: the next call rescans and sees the new tag", %{
    url: url,
    c4: c4,
    c4_raw: c4_raw,
    ref_store: ref_store
  } do
    assert {:ok, []} = GitRepo.tags_containing(url, c4)
    [{pid, _value}] = Registry.lookup(@registry, url)

    {:ok, _ref_store} = RefStore.write(ref_store, "refs/tags/v3.0.0", c4_raw, [])

    # Still the memoized answer within the server's life.
    assert {:ok, []} = GitRepo.tags_containing(url, c4)

    # Simulate the 900s GenServer timeout firing.
    ref = Process.monitor(pid)
    send(pid, :timeout)
    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000
    assert [] = Registry.lookup(@registry, url)

    assert {:ok, ["v3.0.0"]} = GitRepo.tags_containing(url, c4)
    assert {:ok, tags} = GitRepo.all_tags(url)
    assert "v3.0.0" in tags
    assert [{new_pid, _value}] = Registry.lookup(@registry, url)
    refute new_pid == pid
  end

  # The deadline is anchored to the clone/fetch, not to call activity:
  # steady sub-TTL traffic must not postpone expiry.
  test "calls do not extend the deadline", %{url: url, c2: c2} do
    assert {:ok, _tags} = GitRepo.tags_containing(url, c2)
    [{pid, _value}] = Registry.lookup(@registry, url)

    # Age the graph past its deadline, then make one more call: the reply's
    # remaining timeout is 0, so the server stops right after answering
    # instead of getting a fresh 900s from the call.
    :sys.replace_state(pid, fn state ->
      %{state | deadline: System.monotonic_time(:millisecond) - 1}
    end)

    ref = Process.monitor(pid)
    assert {:ok, _tags} = GitRepo.tags_containing(url, c2)
    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000
    assert [] = Registry.lookup(@registry, url)
  end

  # A failed build answers already-queued callers, then stops at the first
  # idle moment. Wait that stop out so the next call is guaranteed a fresh
  # server instead of racing the dying one.
  defp await_server_exit(url) do
    case Registry.lookup(@registry, url) do
      [{pid, _value}] ->
        ref = Process.monitor(pid)
        assert_receive {:DOWN, ^ref, :process, ^pid, _reason}, 1000

      [] ->
        :ok
    end
  end
end
