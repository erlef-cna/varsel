# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.HexIntake.ServiceToken do
  @moduledoc """
  Verifies the short-lived service JWT hex.pm signs its report submissions with.

  The keys come from a JSON JWK Set pinned in configuration, so verification
  never depends on reaching hex.pm. Rotation means updating that value.
  """

  @issuer "hexpm"
  @subject "hexpm"
  @max_lifetime 300

  @type claims :: %{optional(String.t()) => term()}

  @doc """
  Verifies `token` and returns its claims.

  Checks the signature against the configured key set, then that the token
  names hex.pm as issuer and subject, is addressed to `audience`, and is
  currently valid. A `jti` is accepted once; replay within the token's
  lifetime is refused on a best-effort basis, since the counter backing it is
  replicated between nodes asynchronously.
  """
  @spec verify(String.t(), String.t()) :: {:ok, claims()} | {:error, atom()}
  def verify(token, audience) when is_binary(token) and is_binary(audience) do
    with {:ok, kid} <- kid(token),
         {:ok, jwk} <- key(kid),
         {:ok, claims} <- verify_signature(jwk, token),
         {:ok, claims} <- validate_claims(claims, audience) do
      consume(claims)
    end
  end

  defp kid(token) do
    case JOSE.JWT.peek_protected(token) do
      %JOSE.JWS{alg: {:jose_jws_alg_ecdsa, _}, fields: %{"kid" => kid}} -> {:ok, kid}
      _other -> {:error, :malformed_header}
    end
  rescue
    _error -> {:error, :malformed_token}
  end

  defp key(kid) do
    case Map.fetch(keys(), kid) do
      {:ok, jwk} -> {:ok, jwk}
      :error -> {:error, :unknown_key}
    end
  end

  # JOSE parses a JWK Set into a list, dropping the `kid` from each key's
  # struct, so the set is re-read as a map to index the keys by it.
  defp keys do
    jwks =
      :varsel
      |> Application.get_env(:hex_intake, [])
      |> Keyword.get(:jwks)

    with jwks when is_binary(jwks) <- jwks,
         {:ok, %{"keys" => keys}} when is_list(keys) <- JSON.decode(jwks) do
      Map.new(keys, fn key -> {key["kid"], JOSE.JWK.from_map(key)} end)
    else
      _other -> %{}
    end
  end

  # ES256 only: the algorithm is fixed by the sender, and accepting whatever
  # the token's own header asks for is how signature verification gets bypassed.
  defp verify_signature(jwk, token) do
    case JOSE.JWT.verify_strict(jwk, ["ES256"], token) do
      {true, %JOSE.JWT{fields: claims}, _jws} -> {:ok, claims}
      _other -> {:error, :bad_signature}
    end
  end

  defp validate_claims(claims, audience) do
    with :ok <- validate_identity(claims, audience),
         :ok <- validate_validity(claims) do
      {:ok, claims}
    end
  end

  defp validate_identity(claims, audience) do
    cond do
      claims["iss"] != @issuer -> {:error, :bad_issuer}
      claims["sub"] != @subject -> {:error, :bad_subject}
      not audience_matches?(claims["aud"], audience) -> {:error, :bad_audience}
      not is_binary(claims["jti"]) -> {:error, :missing_jti}
      true -> :ok
    end
  end

  defp validate_validity(claims) do
    now = System.system_time(:second)

    cond do
      not is_integer(claims["exp"]) -> {:error, :missing_expiry}
      claims["exp"] <= now -> {:error, :expired}
      is_integer(claims["nbf"]) and claims["nbf"] > now -> {:error, :not_yet_valid}
      not lifetime_ok?(claims, now) -> {:error, :lifetime_too_long}
      true -> :ok
    end
  end

  defp audience_matches?(aud, audience) when is_list(aud), do: audience in aud
  defp audience_matches?(aud, audience), do: aud == audience

  # A token minted far in the past but expiring far in the future would widen
  # the replay window well past what the sender intends (60 seconds).
  defp lifetime_ok?(claims, now) do
    issued = if is_integer(claims["iat"]), do: claims["iat"], else: now

    claims["exp"] - issued <= @max_lifetime
  end

  defp consume(claims) do
    scale = to_timeout(second: @max_lifetime)

    case Varsel.Hammer.hit("hex_intake:jti:#{claims["jti"]}", scale, 1) do
      {:allow, _count} -> {:ok, claims}
      {:deny, _retry_after} -> {:error, :replayed}
    end
  end
end
