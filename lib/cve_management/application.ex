# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      CveManagementWeb.Telemetry,
      CveManagement.Vault,
      CveManagement.Repo,
      {DNSCluster, query: Application.get_env(:cve_management, :dns_cluster_query) || :ignore},
      {Oban,
       AshOban.config(
         Application.fetch_env!(:cve_management, :ash_domains),
         Application.fetch_env!(:cve_management, Oban)
       )},
      {Phoenix.PubSub, name: CveManagement.PubSub},
      # Start a worker by calling: CveManagement.Worker.start_link(arg)
      # {CveManagement.Worker, arg},
      # Start to serve requests, typically the last entry
      CveManagementWeb.Endpoint,
      {AshAuthentication.Supervisor, [otp_app: :cve_management]},
      {Absinthe.Subscription, CveManagementWeb.Endpoint},
      AshGraphql.Subscription.Batcher
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: CveManagement.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    CveManagementWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
