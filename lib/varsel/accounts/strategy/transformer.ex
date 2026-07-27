# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Transformer do
  @moduledoc """
  Runs AshAuthentication's OAuth2 strategy transformation, accepting our own
  identity change in place of the library's.

  The library requires a register action to carry
  `AshAuthentication.Strategy.OAuth2.IdentityChange`, because that change is
  what resolves a sign-in to an account and writes the identity row. Ours does
  the same, wrapping it — see
  `Varsel.Accounts.User.Changes.ResolveOauthIdentity` — but the check compares
  module names, so it refuses.

  Rather than reimplement the transformation (a `with` chain of eight
  validations that would drift), the strategy is transformed against a copy of
  the DSL in which the register action carries the library's change. Only the
  *check* sees that copy; the real action, and everything the transformation
  returns, is untouched.
  """

  alias AshAuthentication.Strategy.OAuth2
  alias AshAuthentication.Strategy.OAuth2.IdentityChange
  alias Spark.Dsl.Transformer
  alias Varsel.Accounts.User.Changes.ResolveOauthIdentity

  @doc false
  @spec transform(struct, map) :: {:ok, struct | map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) do
    case OAuth2.transform(strategy, satisfy_identity_change_check(dsl_state, strategy)) do
      # The returned dsl_state carries the substitution, so the strategy's own
      # additions are replayed onto the real one instead.
      {:ok, transformed} -> {:ok, restore_our_identity_change(transformed, strategy)}
      other -> other
    end
  end

  defp satisfy_identity_change_check(dsl_state, strategy),
    do: swap_identity_change(dsl_state, strategy, ResolveOauthIdentity, IdentityChange)

  defp restore_our_identity_change(dsl_state, strategy),
    do: swap_identity_change(dsl_state, strategy, IdentityChange, ResolveOauthIdentity)

  defp swap_identity_change(dsl_state, strategy, from, to) do
    # `register_action_name` is still nil here: the library fills it in during
    # the very transform this wraps. Deriving the same default it would is the
    # only way to name the action beforehand. `to_existing_atom` because the
    # action is already declared, so its name is already an atom — a name that
    # does not exist is a mistake worth failing on rather than minting.
    action_name =
      strategy.register_action_name ||
        String.to_existing_atom("register_with_#{strategy.name}")

    Transformer.replace_entity(
      dsl_state,
      [:actions],
      swapped_action(dsl_state, action_name, from, to),
      &(&1.name == action_name)
    )
  end

  defp swapped_action(dsl_state, action_name, from, to) do
    dsl_state
    |> Transformer.get_entities([:actions])
    |> Enum.find(&(&1.name == action_name))
    |> then(fn
      nil -> nil
      action -> %{action | changes: Enum.map(action.changes, &swap_change(&1, from, to))}
    end)
  end

  defp swap_change(%{change: {from, opts}} = change, from, to), do: %{change | change: {to, opts}}
  defp swap_change(change, _from, _to), do: change
end
