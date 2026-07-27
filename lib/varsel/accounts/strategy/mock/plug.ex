# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Mock.Plug do
  @moduledoc """
  The callback phase of the mock provider.

  A real provider has a request phase because the browser has to be sent
  somewhere else and redirected back. There is nowhere to send it here: the
  sign-in page offers the roles directly, so a choice arrives already made and
  the callback is the whole flow.
  """

  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  alias AshAuthentication.Strategy
  alias Varsel.Accounts.Strategy.Mock

  @doc false
  @spec handle(Plug.Conn.t(), Mock.t(), :callback) :: Plug.Conn.t()
  def handle(conn, strategy, :callback) do
    with {:ok, uid} <- fetch_uid(conn),
         {:ok, role} <- Mock.role_for(uid),
         {:ok, user} <- register(strategy, uid, role, conn) do
      store_authentication_result(conn, {:ok, user})
    else
      {:error, reason} -> store_authentication_result(conn, {:error, reason})
      :error -> store_authentication_result(conn, :error)
    end
  end

  defp fetch_uid(conn) do
    case conn.params do
      %{"role" => uid} when is_binary(uid) -> {:ok, uid}
      _no_role -> :error
    end
  end

  # The same shape a provider's userinfo would take, so the register action
  # reads it exactly as it reads GitHub's or Hex.pm's.
  defp register(strategy, uid, role, conn) do
    user_info = %{
      "sub" => uid,
      "preferred_username" => "mock-#{uid}",
      "name" => "Mock #{label_for(uid)}",
      "email" => "mock-#{uid}@example.com"
    }

    Strategy.action(
      strategy,
      :register,
      %{user_info: user_info, oauth_tokens: %{}, role: role},
      action_opts(conn)
    )
  end

  defp action_opts(conn) do
    Enum.reject(
      [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn) || %{}],
      &is_nil(elem(&1, 1))
    )
  end

  defp label_for(uid) do
    Enum.find_value(Mock.roles(), uid, fn {u, label, _role} -> if u == uid, do: label end)
  end
end
