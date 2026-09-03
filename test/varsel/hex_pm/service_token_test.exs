# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.HexPm.ServiceTokenTest do
  use ExUnit.Case, async: false

  alias Varsel.HexPm.ServiceToken

  @audience "http://localhost:4000"

  setup do
    original = Application.get_env(:varsel, :hex_signing_key)
    on_exit(fn -> Application.put_env(:varsel, :hex_signing_key, original) end)
    :ok
  end

  test "signs a token hex.pm accepts" do
    {:ok, token} = ServiceToken.sign(@audience)
    now = System.system_time(:second)

    assert %JOSE.JWS{alg: {:jose_jws_alg_ecdsa, :ES256}, fields: %{"kid" => "varsel-test"}} =
             JOSE.JWT.peek_protected(token)

    assert {true, %JOSE.JWT{fields: claims}, _jws} =
             JOSE.JWT.verify_strict(public_key(), ["ES256"], token)

    assert %{"iss" => "varsel", "sub" => "varsel", "aud" => @audience, "jti" => jti} = claims
    assert is_binary(jti)
    assert claims["nbf"] <= now
    assert claims["exp"] > now
    assert claims["exp"] - claims["iat"] <= 300
  end

  test "gives every token its own jti" do
    {:ok, first} = ServiceToken.sign(@audience)
    {:ok, second} = ServiceToken.sign(@audience)

    assert JOSE.JWT.peek_payload(first).fields["jti"] !=
             JOSE.JWT.peek_payload(second).fields["jti"]
  end

  test "refuses to sign without a configured key" do
    Application.delete_env(:varsel, :hex_signing_key)

    assert ServiceToken.sign(@audience) == {:error, :not_configured}
  end

  test "refuses to sign with a key that has no kid" do
    key =
      :varsel |> Application.fetch_env!(:hex_signing_key) |> JSON.decode!() |> Map.delete("kid")

    Application.put_env(:varsel, :hex_signing_key, JSON.encode!(key))

    assert ServiceToken.sign(@audience) == {:error, :not_configured}
  end

  defp public_key do
    :varsel
    |> Application.fetch_env!(:hex_signing_key)
    |> JSON.decode!()
    |> JOSE.JWK.from_map()
    |> JOSE.JWK.to_public()
  end
end
