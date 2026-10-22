# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.OtpVersionsTableTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases.Derivation.OtpVersionsTable
  alias Varsel.Test.GitHubApp

  setup do
    OtpVersionsTable.reset()
    on_exit(&OtpVersionsTable.reset/0)
  end

  test "reads the table raw from the GitHub contents API with the public read token" do
    test_pid = self()
    GitHubApp.seed_installation(%{id: 1, account: "erlef-cna"}, token: "ghs_erlef_cna")

    Req.Test.stub(OtpVersionsTable, fn conn ->
      send(
        test_pid,
        {:github, Plug.Conn.get_req_header(conn, "authorization"), Plug.Conn.get_req_header(conn, "accept")}
      )

      Plug.Conn.send_resp(conn, 200, "OTP-27.0 : ssh-5.2 stdlib-6.0 # erts-15.0 :\n")
    end)

    assert OtpVersionsTable.app_version("27.0", "ssh") == {:ok, "5.2"}

    assert_received {:github, ["Bearer ghs_erlef_cna"], ["application/vnd.github.raw"]}
  end
end
