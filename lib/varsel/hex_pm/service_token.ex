# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.HexPm.ServiceToken do
  @moduledoc """
  Signs the short-lived service token that identifies Varsel to hex.pm.

  The private key is the JSON Web Key in `config :varsel, :hex_signing_key`.
  hex.pm pins the public half and selects it by the key's `kid`.
  `mix generate_hex_service_key` makes such a pair.
  """

  @issuer "varsel"
  @lifetime 60
  @clock_skew 5

  @doc """
  Signs a token addressed to `audience`, the origin of the hex.pm instance.

  The token is valid for #{@lifetime} seconds and carries a `jti` that hex.pm
  accepts once. Returns `{:error, :not_configured}` when no key is set.
  """
  @spec sign(String.t()) :: {:ok, String.t()} | {:error, :not_configured}
  def sign(audience) when is_binary(audience) do
    with {:ok, key} <- key() do
      now = System.system_time(:second)

      claims = %{
        "iss" => @issuer,
        "sub" => @issuer,
        "aud" => audience,
        "iat" => now,
        "nbf" => now - @clock_skew,
        "exp" => now + @lifetime,
        "jti" => Ash.UUID.generate()
      }

      header = %{"alg" => "ES256", "kid" => key["kid"]}

      {_meta, token} =
        key |> JOSE.JWK.from_map() |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

      {:ok, token}
    end
  end

  defp key do
    with jwk when is_binary(jwk) <- Application.get_env(:varsel, :hex_signing_key),
         {:ok, %{"kid" => kid} = key} when is_binary(kid) <- JSON.decode(jwk) do
      {:ok, key}
    else
      _other -> {:error, :not_configured}
    end
  end
end
