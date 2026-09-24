# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Token.LiveSocketId do
  @moduledoc """
  Names the LiveView socket a token opened, so revoking the token can
  disconnect it.
  """

  @doc """
  The socket id for `claims`.

  Sign-in names the socket from the JWT's claims (string keys) and revocation
  from the token row (atom keys), so both spellings must resolve to the same
  topic.
  """
  @spec template(map()) :: String.t()
  def template(claims), do: "users_sessions:#{claims["jti"] || claims[:jti]}"
end
