# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.LiveNotificationsTest do
  use ExUnit.Case, async: true

  alias Ash.Notifier.Notification
  alias Phoenix.Socket.Broadcast
  alias VarselWeb.LiveNotifications

  defp socket(config, assigns) do
    %Phoenix.LiveView.Socket{
      assigns: Map.merge(%{__changed__: %{}, ash_live_config: config}, assigns)
    }
  end

  defp broadcast(topic) do
    %Broadcast{topic: topic, event: "notify", payload: %Notification{}}
  end

  defp config(assign, topics, callback \\ fn _socket -> [:refetched] end) do
    %{
      assign => %{
        last_fetched_at: 0,
        callback: callback,
        opts: [results: :lose],
        subscribed_topics: topics
      }
    }
  end

  test "a topic backed by a live assign is halted and refetched" do
    socket = socket(config(:cases, ["case:all"]), %{cases: []})

    assert {:halt, socket} = LiveNotifications.intercept(broadcast("case:all"), socket)
    assert socket.assigns.cases == [:refetched]
  end

  test "a notification on a topic no live assign covers passes through untouched" do
    socket = socket(config(:cases, ["case:all"]), %{cases: []})

    assert {:cont, socket} = LiveNotifications.intercept(broadcast("chat:lobby"), socket)
    assert socket.assigns.cases == []
  end

  test "a notification passes through when the view has no live assigns at all" do
    socket = socket(%{}, %{})

    assert {:cont, _socket} = LiveNotifications.intercept(broadcast("case:all"), socket)
  end

  test "non-notification messages pass through" do
    socket = socket(config(:cases, ["case:all"]), %{cases: []})
    message = %Broadcast{topic: "case:all", event: "other", payload: :not_a_notification}

    assert {:cont, _socket} = LiveNotifications.intercept(message, socket)
  end

  test "an assign without a subscribe filter refetches on any topic" do
    socket = socket(config(:everything, nil), %{everything: []})

    assert {:halt, socket} = LiveNotifications.intercept(broadcast("whatever:topic"), socket)
    assert socket.assigns.everything == [:refetched]
  end

  test "a same-topic burst is drained into a single refetch" do
    counter = :counters.new(1, [])

    callback = fn _socket ->
      :counters.add(counter, 1, 1)
      [:refetched]
    end

    send(self(), broadcast("case:all"))
    send(self(), broadcast("case:all"))

    socket = socket(config(:cases, ["case:all"], callback), %{cases: []})

    assert {:halt, socket} = LiveNotifications.intercept(broadcast("case:all"), socket)

    assert socket.assigns.cases == [:refetched]
    assert :counters.get(counter, 1) == 1
    refute_received %Broadcast{topic: "case:all"}
  end

  test "draining leaves other topics and messages queued for handle_info" do
    send(self(), broadcast("chat:lobby"))
    send(self(), broadcast("case:all"))
    send(self(), {:some, :other_message})

    socket = socket(config(:cases, ["case:all"]), %{cases: []})

    assert {:halt, _socket} = LiveNotifications.intercept(broadcast("case:all"), socket)

    refute_received %Broadcast{topic: "case:all"}
    assert_received %Broadcast{topic: "chat:lobby"}
    assert_received {:some, :other_message}
  end
end
