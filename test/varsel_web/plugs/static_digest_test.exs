# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.StaticDigestTest do
  use VarselWeb.ConnCase, async: false

  @static_dir Application.app_dir(:varsel, "priv/static")

  # Production links root files by the name `mix phx.digest` gives them.
  for file <- VarselWeb.static_paths(),
      File.regular?(Path.join(@static_dir, file)) do
    test "serves the digested #{file}", %{conn: conn} do
      source = Path.join(@static_dir, unquote(file))
      digest = 16 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
      digested = "#{Path.rootname(unquote(file))}-#{digest}#{Path.extname(unquote(file))}"
      target = Path.join(@static_dir, digested)

      File.cp!(source, target)
      on_exit(fn -> File.rm(target) end)

      assert conn |> get("/#{digested}?vsn=d") |> response(200)
    end
  end
end
