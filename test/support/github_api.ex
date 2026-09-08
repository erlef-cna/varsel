# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.GitHubApi do
  @moduledoc "Stubs GitHub for a test."

  alias Varsel.GitHub.Client

  @doc """
  Stubs GitHub answering every advisory request with `advisory` and every
  profile lookup with the name in `profiles` for that login, or a bare
  profile.
  """
  @spec stub_advisory(map(), %{String.t() => String.t()}) :: :ok
  def stub_advisory(advisory, profiles \\ %{}) do
    stub(fn conn ->
      case conn.path_info do
        ["users", login] ->
          Req.Test.json(conn, %{"login" => login, "name" => profiles[login], "email" => nil})

        _advisory ->
          Req.Test.json(conn, advisory)
      end
    end)
  end

  @doc "Stubs GitHub with `fun`."
  @spec stub((Plug.Conn.t() -> Plug.Conn.t())) :: :ok
  def stub(fun), do: Req.Test.stub(Client, fun)
end
