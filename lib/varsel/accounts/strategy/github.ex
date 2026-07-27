# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Github do
  @moduledoc """
  AshAuthentication's GitHub strategy with our own verifier.

  Identical to `AshAuthentication.Strategy.Github` in every respect except
  that it does not warn about storing an unverified email — see
  `Varsel.Accounts.Strategy.Verifier` for why that warning does not apply
  here. Wrapping the built-in DSL is the only way to reach the verifier, which
  the built-in strategy delegates straight to AshAuthentication's.

  Written as `varsel_github do ... end` because the `github` entity name is
  taken by the built-in strategy; the strategy itself is still named `:github`,
  so routes, the sign-in page and identity rows are unaffected.
  """

  # Built before `use`, which needs the entity at expansion time — an alias
  # declared below it would come too late to apply here.
  @entity %{
    AshAuthentication.Strategy.Github.Dsl.dsl()
    | name: :varsel_github,
      args: [{:optional, :name, :github}]
  }
  use AshAuthentication.Strategy.Custom, entity: @entity

  alias Varsel.Accounts.Strategy.Transformer
  alias Varsel.Accounts.Strategy.Verifier

  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier
end
