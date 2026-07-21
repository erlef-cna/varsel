# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.LiveNotifications do
  @moduledoc """
  `on_mount` hook that keeps every `keep_live` assign fresh from Ash pub_sub
  notifications — no `handle_info` needed in the LiveView.

  Attached in the router's live sessions, it intercepts notification
  broadcasts at the `:handle_info` stage. A broadcast whose topic backs a
  registered `keep_live` assign is halted: further queued notifications on
  the same topic are drained and each assign subscribed to it is refetched
  once. Coalescing matters because one action can emit a notification per
  touched row (reorders, bulk syncs).

  Notification broadcasts on topics no `keep_live` assign covers — e.g. a
  subscription the LiveView made itself — pass through (and are never
  drained), so the LiveView's own `handle_info` still receives them.

  Draining happens before the refetch, inside the intercepted `handle_info`,
  so a drained message's commit is always covered by the refetch's read and
  the refetch stays synchronous with the first notification — later messages
  (including `LiveViewTest` render calls) observe fresh data.
  """

  import Phoenix.LiveView, only: [attach_hook: 4]

  alias Ash.Notifier.Notification
  alias Phoenix.Socket.Broadcast

  def on_mount(:default, _params, _session, socket) do
    {:cont, attach_hook(socket, __MODULE__, :handle_info, &intercept/2)}
  end

  @doc false
  def intercept(%Broadcast{topic: topic, payload: %Notification{}}, socket) do
    case affected_assigns(socket, topic) do
      [] ->
        {:cont, socket}

      assigns ->
        drain(topic)
        {:halt, Enum.reduce(assigns, socket, &AshPhoenix.LiveView.handle_live(&2, :refetch, &1))}
    end
  end

  def intercept(_message, socket), do: {:cont, socket}

  # A keep_live without a subscribe filter refetches on any topic, matching
  # the topic gate of AshPhoenix.LiveView.handle_live/3.
  defp affected_assigns(socket, topic) do
    for {assign, config} <- Map.get(socket.assigns, :ash_live_config, %{}),
        config.subscribed_topics == nil or topic in config.subscribed_topics,
        do: assign
  end

  defp drain(topic) do
    receive do
      %Broadcast{topic: ^topic, payload: %Notification{}} -> drain(topic)
    after
      0 -> :ok
    end
  end
end
