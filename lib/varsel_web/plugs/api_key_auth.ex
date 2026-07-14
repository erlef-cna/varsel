# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.ApiKeyAuth do
  @moduledoc """
  Authenticates `Authorization: Bearer eefcna_...` API keys.

  Only engages when the bearer token carries the API-key prefix; JWTs (or no
  header at all) fall through untouched so `load_from_bearer` / anonymous
  access keep working on the same pipeline. A present-but-invalid API key is
  a hard 401 (`AshAuthentication.Strategy.ApiKey.Plug` halts even with
  `required?: false`, which is why the prefix dispatch lives here).
  """
  @behaviour Plug

  alias AshAuthentication.Strategy.ApiKey

  @prefix "Bearer eefcna_"

  @impl Plug
  def init(_opts), do: ApiKey.Plug.init(resource: Varsel.Accounts.User)

  @impl Plug
  def call(conn, config) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      [@prefix <> _ | _] -> ApiKey.Plug.call(conn, config)
      _other -> conn
    end
  end
end
