# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.HexServiceTokenFixture do
  @moduledoc """
  Signs service tokens the way hex.pm does, with the private half of the key
  `config/test.exs` pins for hex intake.
  """

  @signing_key %{
    "crv" => "P-256",
    "d" => "qgBTDHU-tA41X5luD1wc3vjM40y03pudRLsRVGHsWZA",
    "kty" => "EC",
    "x" => "4pRM_ZlHTfTHVvAIxDEBraNmq06ojzDzL2MIHUzkqLk",
    "y" => "5HMC6Ycg9OjJGFbFs46n8rCTxB6VyGWcsLR3bnNWEtU"
  }

  @doc "A valid token addressed to `audience`, with `claims` overriding the defaults."
  def sign(audience, claims \\ %{}) do
    now = System.system_time(:second)

    claims =
      Enum.into(claims, %{
        "aud" => audience,
        "exp" => now + 60,
        "iat" => now,
        "iss" => "hexpm",
        "jti" => Ash.UUID.generate(),
        "nbf" => now - 5,
        "sub" => "hexpm"
      })

    {_meta, token} =
      @signing_key
      |> JOSE.JWK.from_map()
      |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => "hexpm-test"}, claims)
      |> JOSE.JWS.compact()

    token
  end
end
