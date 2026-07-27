# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Transformer do
  @moduledoc """
  Runs AshAuthentication's OAuth2 strategy transformation against a register
  action shaped the way it expects, while the real one differs in two ways.

  It requires the action to carry
  `AshAuthentication.Strategy.OAuth2.IdentityChange`, which resolves a sign-in
  to an account and writes the identity row. Ours does that itself — see
  `Varsel.Accounts.User.Changes.ResolveOauthIdentity` — but the check compares
  module names.

  It also requires an `upsert_identity`, on the assumption that a returning
  user is found by matching some attribute. Ours is found through their
  identity row, which names the account outright, so the action deliberately
  has none and upserts on the primary key.

  Rather than reimplement the transformation (a `with` chain of eight
  validations that would drift), it runs against a copy of the DSL carrying
  both. Only the checks see that copy; the real action, and everything the
  transformation returns, is untouched.
  """

  alias AshAuthentication.Strategy.OAuth2
  alias AshAuthentication.Strategy.OAuth2.IdentityChange
  alias Spark.Dsl.Transformer
  alias Varsel.Accounts.User.Changes.ResolveOauthIdentity

  @doc false
  @spec transform(struct, map) :: {:ok, struct | map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) do
    case OAuth2.transform(strategy, satisfy_checks(dsl_state, strategy)) do
      # The returned dsl_state carries the substitutions, so the strategy's own
      # additions are replayed onto the real action instead.
      {:ok, transformed} -> {:ok, restore(transformed, strategy)}
      other -> other
    end
  end

  defp satisfy_checks(dsl_state, strategy) do
    dsl_state
    |> swap_identity_change(strategy, ResolveOauthIdentity, IdentityChange)
    |> put_upsert_identity(strategy, :unique_notification_email)
  end

  defp restore(dsl_state, strategy) do
    dsl_state
    |> swap_identity_change(strategy, IdentityChange, ResolveOauthIdentity)
    |> put_upsert_identity(strategy, nil)
  end

  defp put_upsert_identity(dsl_state, strategy, identity) do
    update_register_action(dsl_state, strategy, &%{&1 | upsert_identity: identity})
  end

  defp swap_identity_change(dsl_state, strategy, from, to) do
    update_register_action(dsl_state, strategy, fn action ->
      %{action | changes: Enum.map(action.changes, &swap_change(&1, from, to))}
    end)
  end

  defp update_register_action(dsl_state, strategy, fun) do
    # `register_action_name` is still nil here: the library fills it in during
    # the very transform this wraps. Deriving the same default it would is the
    # only way to name the action beforehand. `to_existing_atom` because the
    # action is already declared, so its name is already an atom — a name that
    # does not exist is a mistake worth failing on rather than minting.
    action_name =
      strategy.register_action_name ||
        String.to_existing_atom("register_with_#{strategy.name}")

    case Enum.find(Transformer.get_entities(dsl_state, [:actions]), &(&1.name == action_name)) do
      nil ->
        dsl_state

      action ->
        Transformer.replace_entity(
          dsl_state,
          [:actions],
          fun.(action),
          &(&1.name == action_name)
        )
    end
  end

  defp swap_change(%{change: {from, opts}} = change, from, to), do: %{change | change: {to, opts}}
  defp swap_change(change, _from, _to), do: change
end
