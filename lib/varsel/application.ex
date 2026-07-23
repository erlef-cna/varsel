# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl Application
  def start(_type, _args) do
    children = [
      {AshAuthentication.Oauth2Server.Supervisor, [otp_app: :varsel]},
      VarselWeb.Telemetry,
      Varsel.Vault,
      Varsel.Repo,
      {DNSCluster, query: Application.get_env(:varsel, :dns_cluster_query) || :ignore},
      {Oban,
       AshOban.config(
         Application.fetch_env!(:varsel, :ash_domains),
         Application.fetch_env!(:varsel, Oban)
       )},
      {Phoenix.PubSub, name: Varsel.PubSub},
      {Varsel.Cases.Derivation.GitRepo, []},
      # Start a worker by calling: Varsel.Worker.start_link(arg)
      # {Varsel.Worker, arg},
      # Start to serve requests, typically the last entry
      VarselWeb.Endpoint,
      {AshAuthentication.Supervisor, [otp_app: :varsel]},
      {Absinthe.Subscription, VarselWeb.Endpoint},
      AshGraphql.Subscription.Batcher
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Varsel.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl Application
  def config_change(changed, _new, removed) do
    VarselWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
