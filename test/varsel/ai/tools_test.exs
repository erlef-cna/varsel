# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.AI.ToolsTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Unknown.UnknownError
  alias Varsel.AI.Tools
  alias Varsel.Fixtures

  setup do
    %{poc: Fixtures.register_user("ai_tools_poc", :poc)}
  end

  defp hex_package_info(name, actor) do
    Tools
    |> Ash.ActionInput.for_action(:hex_package_info, %{name: name})
    |> Ash.run_action(actor: actor)
  end

  test "hex_package_info returns the package details", %{poc: poc} do
    Application.put_env(:varsel, :hex_stub_packages, %{"acme_lib" => ["1.0.0", "1.1.0"]})
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)

    assert {:ok, info} = hex_package_info("acme_lib", poc)
    assert info["exists"]
    assert info["versions"] == ["1.0.0", "1.1.0"]
  end

  test "a missing package is a finding, not an error", %{poc: poc} do
    # An OTP application like xmerl is not on hex.pm; the assistant must get
    # a readable result instead of a generic tool failure it retries blindly.
    assert {:ok, info} = hex_package_info("xmerl", poc)
    refute info["exists"]
    assert info["note"] =~ "OTP application"
  end

  test "string errors from tool actions reach the model verbatim" do
    error = UnknownError.exception(error: "hex.pm returned 503 for acme_lib")

    assert AshAi.ToToolError.to_tool_error(error) == "hex.pm returned 503 for acme_lib"
  end
end
