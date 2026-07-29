# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Notifiers.DisconnectSockets do
  @moduledoc """
  Closes open sockets when the authority behind them is withdrawn: an API key
  deleted, a role changed, an account deleted.

  Sockets resolve their actor once and keep it, so the change has to be pushed
  to the connection (`VarselWeb.SocketDisconnect`).
  """

  use Ash.Notifier

  alias Ash.Notifier.Notification
  alias VarselWeb.SocketDisconnect

  @impl Ash.Notifier
  def notify(%Notification{resource: Varsel.Accounts.ApiKey, data: api_key}) do
    SocketDisconnect.broadcast(SocketDisconnect.api_key_topic(api_key.id))

    :ok
  end

  def notify(%Notification{resource: Varsel.Accounts.User, data: user} = notification) do
    if role_changed?(notification) or notification.action.type == :destroy do
      SocketDisconnect.broadcast(SocketDisconnect.user_topic(user.id))
    end

    :ok
  end

  def notify(_other), do: :ok

  # The role is the authority a socket resolved at connect, so a change to it
  # is what has to reach the connection.
  defp role_changed?(%Notification{action: %{type: :update}, changeset: changeset}) do
    Ash.Changeset.changing_attribute?(changeset, :role)
  end

  defp role_changed?(_other), do: false
end
