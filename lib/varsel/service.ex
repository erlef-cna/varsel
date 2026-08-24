# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Service do
  @moduledoc """
  The actor a verified sending system runs as.

  A sending system is an identity like any other, so it is passed to actions
  as one and checked by policies the way a user is. Each system's actor is
  built in exactly one place, after that system's credential verifies.

  It carries a `role` because the role checks written for users are not
  total: `actor_attribute_equals` raises on an actor it cannot `Map.fetch`,
  so an actor without one would break every policy that shares a block with
  a role check. `:system` matches none of them.
  """

  @enforce_keys [:system]
  defstruct [:system, role: :system]

  @typedoc """
  Which sending system the actor stands for. Policies authorize on it with
  `actor_attribute_equals(:system, ...)`.
  """
  @type system() :: system_hexpm_intake()

  @typedoc """
  hex.pm's package-report intake, verified by `VarselWeb.Plugs.HexServiceAuth`.
  """
  @type system_hexpm_intake() :: :hexpm_intake

  @type t() :: %__MODULE__{system: system(), role: :system}

  @doc "The actor for a verified hex.pm submission."
  @spec hexpm_intake() :: t()
  def hexpm_intake, do: %__MODULE__{system: :hexpm_intake}
end
