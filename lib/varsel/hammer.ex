# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Hammer do
  @moduledoc """
  Rate limiting backend for `AshRateLimiter`.

  Counters live in a per-node ETS table, replicated across the cluster over
  `Varsel.PubSub`: a hit is applied locally and broadcast to the other nodes,
  which apply it to their own table without re-broadcasting. Without this every
  machine would keep an independent count and a limit of `n` would effectively
  become `n * <machine count>`.

  Replication is eventually consistent, so the enforced limit is approximate:
  hits racing on two nodes can each be allowed before the other's broadcast
  lands, and a node that starts or restarts begins with empty counters.
  """

  use Supervisor

  @pubsub Varsel.PubSub
  @topic "hammer:inc"

  defmodule Local do
    @moduledoc """
    Node-local ETS counters backing `Varsel.Hammer`.

    Called directly only by `Varsel.Hammer` and its listener; everything else
    goes through `Varsel.Hammer` so hits get replicated.
    """

    use Hammer, backend: :ets
  end

  defmodule Listener do
    @moduledoc """
    Applies rate limit hits broadcast by the other nodes to this node's table.
    """

    use GenServer

    @doc false
    def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

    @impl GenServer
    def init(opts) do
      pubsub = Keyword.fetch!(opts, :pubsub)
      topic = Keyword.fetch!(opts, :topic)
      :ok = Phoenix.PubSub.subscribe(pubsub, topic)
      {:ok, %{}}
    end

    @impl GenServer
    def handle_info({:inc, origin, _key, _scale, _increment}, state) when origin == node() do
      # The originating node already applied this hit via `Varsel.Hammer.hit/4`.
      # PubSub delivers to every subscriber on every node, and the broadcaster
      # is a different process than this one, so the local copy must be dropped
      # here or every local hit would count twice.
      {:noreply, state}
    end

    def handle_info({:inc, _origin, key, scale, increment}, state) do
      # `inc` rather than `hit`: the originating node already decided whether
      # the call was allowed, and this side must not re-broadcast.
      Local.inc(key, scale, increment)
      {:noreply, state}
    end
  end

  @doc false
  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)

  @impl Supervisor
  def init(opts) do
    children = [
      {Local, opts},
      {Listener, pubsub: @pubsub, topic: @topic}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  @doc """
  Registers a hit against `key`, replicating it to the other nodes.

  Returns `{:allow, count}` or `{:deny, retry_after_ms}` from this node's view
  of the counter.
  """
  def hit(key, scale, limit, increment \\ 1) do
    :ok = Phoenix.PubSub.broadcast!(@pubsub, @topic, {:inc, node(), key, scale, increment})
    Local.hit(key, scale, limit, increment)
  end

  @doc """
  Returns the current count for `key` in the current window on this node.
  """
  defdelegate get(key, scale), to: Local
end
