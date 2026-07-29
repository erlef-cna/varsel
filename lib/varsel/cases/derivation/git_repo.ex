# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.GitRepo do
  @moduledoc """
  `Varsel.Cases.Derivation.GitBackend` implementation on `exgit` — pure
  Elixir, no git binary or libgit2 at runtime.

  One `Varsel.Cases.Derivation.GitRepo.Server` per repository URL (Registry +
  DynamicSupervisor under `Varsel.Cases.Derivation.GitRepo.Supervisor`),
  started by whichever call arrives first. The server pays the expensive scan
  once and serves memoized answers until it expires, unregisters, and stops;
  the next call starts a fresh server and rescans. Graph and memoized answers
  therefore share one lifecycle by construction — a new release tag becomes
  visible on every code path at once, and no answer can outlive the scan it
  came from. One slow repository blocks only its own server.
  """

  @behaviour Varsel.Cases.Derivation.GitBackend

  alias Varsel.Cases.Derivation.GitBackend
  alias Varsel.Cases.Derivation.GitRepo.Server

  @registry Varsel.Cases.Derivation.GitRepo.Registry
  @supervisor Varsel.Cases.Derivation.GitRepo.DynamicSupervisor

  # The first call per repository pays for the full clone + graph walk.
  @call_timeout to_timeout(minute: 10)

  @impl GitBackend
  def tags_containing(repo_url, sha), do: call(repo_url, {:tags_containing, sha})

  @impl GitBackend
  def all_tags(repo_url), do: call(repo_url, :all_tags)

  @impl GitBackend
  def refresh(repo_url) do
    case Registry.lookup(@registry, repo_url) do
      [{pid, _value}] -> refresh_server(pid)
      [] -> :ok
    end
  end

  # The reply is ignored: an errored server answers {:error, _} and stops on
  # its own, and refresh's contract is only that subsequent queries see fresh
  # data — which a stopped server satisfies by rescanning on the next call.
  defp refresh_server(pid) do
    _ = GenServer.call(pid, :refresh, @call_timeout)
    :ok
  catch
    # Lost the race against the server's own expiry — already gone.
    :exit, _reason -> :ok
  end

  # Start-first, no lookup: unique registration makes starting idempotent, so
  # the only remaining race is the server expiring between start and call;
  # that exits the call and is retried once against a fresh server.
  defp call(repo_url, request, retry? \\ true) do
    GenServer.call(server(repo_url), request, @call_timeout)
  catch
    :exit, {reason, {GenServer, :call, _args}}
    when retry? and reason in [:noproc, :normal, :shutdown] ->
      call(repo_url, request, false)
  end

  defp server(repo_url) do
    case DynamicSupervisor.start_child(@supervisor, {Server, repo_url}) do
      {:ok, pid} -> pid
      {:error, {:already_started, pid}} -> pid
    end
  end
end
