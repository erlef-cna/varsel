# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.SignInDetails do
  @moduledoc """
  Carries the browser and address a request came from into whichever action
  ends up storing a session token, for the account page's session list.
  """
  @behaviour Plug

  # Attacker-controlled and unbounded; only the start of it is ever shown.
  @user_agent_limit 100

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    Ash.PlugHelpers.set_context(conn, %{
      # `:shared` is the only part of a context Ash carries into nested actions.
      shared: %{
        sign_in_details: %{
          "user_agent" => user_agent(conn),
          "ip" => conn.remote_ip |> :inet.ntoa() |> to_string()
        }
      }
    })
  end

  defp user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [agent | _rest] when is_binary(agent) -> String.slice(agent, 0, @user_agent_limit)
      _absent -> nil
    end
  end
end
