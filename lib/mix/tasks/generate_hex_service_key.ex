# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.GenerateHexServiceKey do
  @shortdoc "Generates the key pair that signs service tokens for hex.pm"

  @moduledoc """
  Generates an ES256 key pair for the service tokens Varsel sends to hex.pm.

  The task prints two keys and writes no file:

  1. The private key, as a JSON Web Key. Set it as `HEX_SIGNING_KEY` on this
     deployment. It is a secret.
  2. The public key, as a JSON Web Key. Add it to the `keys` list of hex.pm's
     `HEXPM_VARSEL_JWKS` setting.

  Both keys carry the same `kid`. hex.pm selects the public key by that value,
  so give each key pair a `kid` that no other key in hex.pm's list uses.

  Usage:

      mix generate_hex_service_key --kid varsel-prod
  """

  use Mix.Task

  @requirements ["loadpaths"]

  @impl Mix.Task
  def run(args) do
    {opts, []} = OptionParser.parse!(args, strict: [kid: :string])

    kid =
      case Keyword.fetch(opts, :kid) do
        {:ok, kid} ->
          kid

        :error ->
          Mix.raise("--kid is required. Example: mix generate_hex_service_key --kid varsel-prod")
      end

    {:ok, _apps} = Application.ensure_all_started(:jose)

    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_meta, private} = JOSE.JWK.to_map(jwk)
    {_meta, public} = JOSE.JWK.to_public_map(jwk)

    Mix.shell().info("""
    Private key. Set HEX_SIGNING_KEY on this deployment to this value:

    #{JSON.encode!(Map.put(private, "kid", kid))}

    Public key. Add this entry to the "keys" list in hex.pm's HEXPM_VARSEL_JWKS:

    #{JSON.encode!(Map.put(public, "kid", kid))}
    """)
  end
end
