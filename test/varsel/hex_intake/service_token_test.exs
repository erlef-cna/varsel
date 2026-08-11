# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.HexIntake.ServiceTokenTest do
  use ExUnit.Case, async: false

  alias Varsel.HexIntake.ServiceToken

  @audience "http://localhost:4002/api/hex/reports"

  @signing_key %{
    "crv" => "P-256",
    "d" => "qgBTDHU-tA41X5luD1wc3vjM40y03pudRLsRVGHsWZA",
    "kty" => "EC",
    "x" => "4pRM_ZlHTfTHVvAIxDEBraNmq06ojzDzL2MIHUzkqLk",
    "y" => "5HMC6Ycg9OjJGFbFs46n8rCTxB6VyGWcsLR3bnNWEtU"
  }

  defp sign(claims, opts \\ []) do
    now = System.system_time(:second)

    claims =
      Enum.into(claims, %{
        "aud" => @audience,
        "exp" => now + 60,
        "iat" => now,
        "iss" => "hexpm",
        "jti" => Ash.UUID.generate(),
        "nbf" => now - 5,
        "sub" => "hexpm"
      })

    jwk = JOSE.JWK.from_map(Keyword.get(opts, :key, @signing_key))
    header = %{"alg" => "ES256", "kid" => Keyword.get(opts, :kid, "hexpm-test")}

    {_meta, token} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    token
  end

  describe "a token hex.pm would send" do
    test "verifies and returns its claims" do
      assert {:ok, claims} = ServiceToken.verify(sign(%{}), @audience)
      assert claims["iss"] == "hexpm"
    end

    test "is refused a second time" do
      token = sign(%{})

      assert {:ok, _claims} = ServiceToken.verify(token, @audience)
      assert {:error, :replayed} = ServiceToken.verify(token, @audience)
    end
  end

  describe "refuses" do
    test "a signature from a key we do not know" do
      other = JOSE.JWK.generate_key({:ec, :secp256r1})
      {_type, key} = JOSE.JWK.to_map(other)

      assert {:error, :bad_signature} = ServiceToken.verify(sign(%{}, key: key), @audience)
    end

    test "a kid that is not in the key set" do
      assert {:error, :unknown_key} = ServiceToken.verify(sign(%{}, kid: "rotated"), @audience)
    end

    test "a token addressed to someone else" do
      token = sign(%{"aud" => "https://example.com/api/hex/reports"})

      assert {:error, :bad_audience} = ServiceToken.verify(token, @audience)
    end

    test "an issuer that is not hex.pm" do
      assert {:error, :bad_issuer} = ServiceToken.verify(sign(%{"iss" => "evil"}), @audience)
    end

    test "a subject that is not hex.pm" do
      assert {:error, :bad_subject} =
               ServiceToken.verify(sign(%{"sub" => "user:mallory"}), @audience)
    end

    test "an expired token" do
      now = System.system_time(:second)
      token = sign(%{"iat" => now - 120, "exp" => now - 60, "nbf" => now - 120})

      assert {:error, :expired} = ServiceToken.verify(token, @audience)
    end

    test "a token that is not valid yet" do
      now = System.system_time(:second)
      token = sign(%{"nbf" => now + 60, "exp" => now + 120})

      assert {:error, :not_yet_valid} = ServiceToken.verify(token, @audience)
    end

    test "a lifetime far longer than the sender mints" do
      now = System.system_time(:second)
      token = sign(%{"iat" => now, "exp" => now + 86_400})

      assert {:error, :lifetime_too_long} = ServiceToken.verify(token, @audience)
    end

    test "a token with no jti to track" do
      now = System.system_time(:second)

      token =
        sign(%{"jti" => nil, "iat" => now, "exp" => now + 60})

      assert {:error, :missing_jti} = ServiceToken.verify(token, @audience)
    end

    test "something that is not a token at all" do
      assert {:error, _reason} = ServiceToken.verify("not-a-token", @audience)
    end

    # Hand-assembled: JOSE will not sign this, which is the point. An attacker
    # forges the bytes rather than asking a library for them.
    test "an unsigned token claiming alg none" do
      now = System.system_time(:second)

      encode = fn map ->
        map |> JSON.encode!() |> Base.url_encode64(padding: false)
      end

      header = encode.(%{"alg" => "none", "kid" => "hexpm-test"})

      payload =
        encode.(%{
          "aud" => @audience,
          "exp" => now + 60,
          "iss" => "hexpm",
          "jti" => Ash.UUID.generate(),
          "sub" => "hexpm"
        })

      assert {:error, _reason} = ServiceToken.verify("#{header}.#{payload}.", @audience)
    end
  end
end
