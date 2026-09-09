# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.RefusalTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.GitHubAdvisory.Refusal

  @not_found "was refused: GitHub shows you no such advisory"

  test "an advisory or repository GitHub does not show the caller is stated in the action's terms" do
    assert Refusal.message(:not_found, @not_found) == @not_found
  end

  test "a token GitHub no longer accepts asks for a new sign-in" do
    assert Refusal.message({:error, :unauthorized}, @not_found) ==
             "needs you to sign in with GitHub again"
  end

  test "a refusal with GitHub's message carries it" do
    assert Refusal.message(
             {:error, {:http, 403, %{"message" => "Private vulnerability reporting is disabled"}}},
             @not_found
           ) ==
             "was refused by GitHub: Private vulnerability reporting is disabled"
  end

  test "a refusal without a JSON message names the status" do
    assert Refusal.message({:error, {:http, 403, "<html>Forbidden</html>"}}, @not_found) ==
             "was refused by GitHub (HTTP 403)"
  end

  test "a GitHub that cannot be reached is stated as such" do
    assert Refusal.message({:error, %Req.TransportError{reason: :econnrefused}}, @not_found) ==
             "could not reach GitHub"
  end
end
