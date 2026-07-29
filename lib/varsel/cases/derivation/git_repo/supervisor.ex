# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.GitRepo.Supervisor do
  @moduledoc """
  Registry + DynamicSupervisor for the per-repository
  `Varsel.Cases.Derivation.GitRepo.Server` processes.
  """

  use Supervisor

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl Supervisor
  def init(_opts) do
    children = [
      {Registry, keys: :unique, name: Varsel.Cases.Derivation.GitRepo.Registry},
      {DynamicSupervisor, name: Varsel.Cases.Derivation.GitRepo.DynamicSupervisor, strategy: :one_for_one}
    ]

    # rest_for_one: if the Registry dies the servers' registrations are gone
    # with it, so the DynamicSupervisor (and its servers) must restart too.
    Supervisor.init(children, strategy: :rest_for_one)
  end
end
