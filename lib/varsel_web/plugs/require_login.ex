# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.RequireLogin do
  @moduledoc """
  Sends an anonymous caller to sign in, and back to the page they asked for
  once they are.

  Pages that only mean anything for a signed-in user get this rather than an
  empty version of themselves. The return trip is `VarselWeb.SignInPath`'s
  doing: it puts the current path on the sign-in link, and
  `VarselWeb.Plugs.ReturnPath` parks it in the session for
  `VarselWeb.AuthController.success/4` to spend.

  Runs after whatever fills in `:current_user` (`load_from_session` on the
  `:browser` pipeline), since that assign is the whole question.
  """
  @behaviour Plug

  import Phoenix.Controller, only: [redirect: 2]
  import Plug.Conn, only: [halt: 1]

  alias VarselWeb.SignInPath

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Plug.Conn{assigns: %{current_user: user}} = conn, _opts) when not is_nil(user), do: conn

  def call(conn, _opts) do
    conn
    |> redirect(to: SignInPath.for(conn))
    |> halt()
  end
end
