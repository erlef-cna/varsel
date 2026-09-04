# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.GenerateHexServiceKeyTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Mix.Tasks.GenerateHexServiceKey

  test "prints a private key and its public half under the given kid" do
    {private, public} = generate(["--kid", "varsel-example"])

    assert %{"kty" => "EC", "crv" => "P-256", "kid" => "varsel-example", "d" => _d} = private
    assert %{"kty" => "EC", "crv" => "P-256", "kid" => "varsel-example"} = public
    refute Map.has_key?(public, "d")
    assert Map.take(public, ["x", "y"]) == Map.take(private, ["x", "y"])

    signed = JOSE.JWT.sign(JOSE.JWK.from_map(private), %{"alg" => "ES256"}, %{"iss" => "varsel"})
    {_meta, token} = JOSE.JWS.compact(signed)

    assert {true, %JOSE.JWT{fields: %{"iss" => "varsel"}}, _jws} =
             JOSE.JWT.verify_strict(JOSE.JWK.from_map(public), ["ES256"], token)
  end

  test "refuses to run without a kid" do
    assert_raise Mix.Error, ~r/--kid is required/, fn -> GenerateHexServiceKey.run([]) end
  end

  test "generates a different key on every run" do
    {first, _public} = generate(["--kid", "varsel-example"])
    {second, _public} = generate(["--kid", "varsel-example"])

    assert first["d"] != second["d"]
  end

  defp generate(args) do
    output = capture_io(fn -> GenerateHexServiceKey.run(args) end)

    [private, public] =
      output
      |> String.split("\n")
      |> Enum.filter(&String.starts_with?(&1, "{"))
      |> Enum.map(&JSON.decode!/1)

    {private, public}
  end
end
