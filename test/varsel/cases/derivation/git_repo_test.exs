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

  # Commit graph (main holds only c3; everything else is tag/branch-only):
  #
  #   c1 ── c2 ── c3            tags: v1.0.0 (annotated -> c2), v2.0.0 -> c3
  #     └── b1                  tag:  v1.5.0 -> b1 (side branch)
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
    {b1, store} = commit.(store, [c1], "b1")

    {:ok, annotated, store} =
      ObjectStore.put(
        store,
        Tag.new(object: c2, tag: "v1.0.0", tagger: @person, message: "v1.0.0")
      )

    ref_store = repo.ref_store
    {:ok, ref_store} = RefStore.write(ref_store, "refs/heads/main", c3, [])
    {:ok, ref_store} = RefStore.write(ref_store, "refs/heads/backport", b1, [])
    {:ok, ref_store} = RefStore.write(ref_store, "refs/tags/v1.0.0", annotated, [])
    {:ok, ref_store} = RefStore.write(ref_store, "refs/tags/v1.5.0", b1, [])
    {:ok, _ref_store} = RefStore.write(ref_store, "refs/tags/v2.0.0", c3, [])

    _ = store

    %{url: "file://" <> dir, c1: hex(c1), c2: hex(c2), b1: hex(b1)}
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
end
