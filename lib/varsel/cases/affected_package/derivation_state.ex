# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.DerivationState do
  @moduledoc """
  What a product's cached derivation is worth right now.

  Deriving is explicit — it walks a repository and the registries it publishes
  to — so the version ranges on screen can be anything from authoritative to
  actively misleading, and nothing about the ranges themselves says which.
  This names the difference:

    * `:never` — nothing has run, so empty ranges mean "unknown", not "none".
    * `:outdated` — a boundary fact, a channel, or the product itself changed
      after the last run, so the ranges are wrong. Publishing blocks on it.
    * `:ageing` — ran after every change we know about, but long enough ago
      that releases may have been cut since. Nothing in the case is wrong; the
      world may simply have moved.
    * `:current` — ran after every change we know about, recently.
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      never: "No derivation has run; the product claims no versions yet.",
      outdated: "The facts changed after the last derivation, so its ranges are wrong.",
      ageing: "Derived after every known change, but long enough ago that releases may have followed.",
      current: "Derived after every known change."
    ]

  # How long a derivation is taken at face value before it reads as ageing.
  # A day is roughly the cadence at which the ecosystems we track cut releases,
  # so it is the point where "nothing changed here" stops implying "nothing
  # changed anywhere".
  @ageing_after_hours 24

  # How loudly each state needs to be answered, so a case of several products
  # can report the one that most needs attention. Ordered rather than compared
  # by name because the states have no alphabetical relationship.
  @severity %{current: 0, ageing: 1, never: 2, outdated: 3}

  @doc "Hours after which a current derivation reads as ageing."
  @spec ageing_after_hours() :: pos_integer()
  def ageing_after_hours, do: @ageing_after_hours

  @doc """
  How loudly a state needs answering — higher is worse. `:never` outranks
  `:ageing` because nothing has been derived at all, while an ageing result is
  still a result.
  """
  @spec severity(t()) :: non_neg_integer()
  def severity(state), do: Map.fetch!(@severity, state)

  @doc """
  The state a group of products reports as a whole: the one that most needs
  attention, since a case is only as derived as its least-derived product.
  Nothing to report without any products.
  """
  @spec worst([t()]) :: t() | nil
  def worst([]), do: nil
  def worst(states), do: Enum.max_by(states, &severity/1)

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :affected_package_derivation_state

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :affected_package_derivation_state
end
