# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequest.Changes.MintToken do
  @moduledoc """
  Mints the one-time token of a new manual request: an AshAuthentication
  token of the POC, purpose `github_manual`, valid for 15 minutes, with the
  request's id as its `request_id` claim.

  The mint stores the token's row in `Varsel.Accounts.Token` inside the
  create's transaction, before the request's own insert, which references
  that row by its jti. A failed insert takes the token row back with it. The
  plaintext token becomes the created record's `token` metadata, and nothing
  else holds it.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias AshAuthentication.Jwt

  @lifetime {15, :minutes}

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    changeset
    |> Changeset.before_action(&mint(&1, context.actor))
    |> Changeset.after_action(fn changeset, request ->
      {:ok, Ash.Resource.put_metadata(request, :token, changeset.context[:github_manual_token])}
    end)
  end

  defp mint(%{valid?: false} = changeset, _actor), do: changeset

  defp mint(changeset, actor) do
    claims = %{"request_id" => Changeset.get_attribute(changeset, :id)}

    case Jwt.token_for_user(actor, claims, purpose: :github_manual, token_lifetime: @lifetime) do
      {:ok, token, %{"jti" => jti}} ->
        changeset
        |> Changeset.force_change_attribute(:token_id, jti)
        |> Changeset.put_context(:github_manual_token, token)

      {:error, error} ->
        Changeset.add_error(changeset, error)
    end
  end
end
