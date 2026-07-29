# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.SocketDisconnect do
  @moduledoc """
  Topics for closing sockets whose authority has been withdrawn.

  A socket subscribes to the credential that opened it and to its user, and
  `Varsel.Accounts.Notifiers.DisconnectSockets` broadcasts on them.
  """

  @doc """
  The topic naming a user, for role and account-deletion disconnects.
  """
  @spec user_topic(Ash.UUID.t()) :: String.t()
  def user_topic(user_id), do: "users:#{user_id}"

  @doc """
  The topic naming an API key, for revocation disconnects.
  """
  @spec api_key_topic(Ash.UUID.t()) :: String.t()
  def api_key_topic(api_key_id), do: "api_keys:#{api_key_id}"

  @doc """
  Closes every socket authenticated by `topic`.
  """
  @spec broadcast(String.t()) :: :ok
  def broadcast(topic) do
    VarselWeb.Endpoint.broadcast(topic, "disconnect", %{})
  end
end
