# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.StubGitBackend do
  @moduledoc """
  Test double for `Varsel.Cases.Derivation.GitBackend`.

  Tests declare the repo state with `stub_tags/1`:

      StubGitBackend.stub_tags(%{
        {"https://github.com/acme/pkg", "aaaa..."} => ["v1.0.0", "v2.0.0"],
        {"https://github.com/acme/pkg", "bbbb..."} => []   # commit known, unreleased
      })

  Unknown `{repo, sha}` pairs answer `{:error, :commit_not_found}`.
  """

  @behaviour Varsel.Cases.Derivation.GitBackend

  @key {__MODULE__, :tags}

  @spec stub_tags(%{{String.t(), String.t()} => [String.t()]}) :: :ok
  def stub_tags(tags) do
    :persistent_term.put(@key, tags)
    ExUnit.Callbacks.on_exit(fn -> :persistent_term.erase(@key) end)
    :ok
  end

  @impl Varsel.Cases.Derivation.GitBackend
  def tags_containing(repo_url, sha) do
    case Map.fetch(:persistent_term.get(@key, %{}), {repo_url, sha}) do
      {:ok, tags} -> {:ok, tags}
      :error -> {:error, :commit_not_found}
    end
  end
end
