# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.HexIntake.Service do
  @moduledoc """
  The actor a verified hex.pm submission runs as.

  A sending system is an identity like any other, so it is passed to actions
  as one and checked by policies the way a user is. Only
  `VarselWeb.Plugs.HexServiceAuth` builds it, and only after verifying the
  service token.

  It carries a `role` because the role checks written for users are not
  total: `actor_attribute_equals` raises on an actor it cannot `Map.fetch`,
  so an actor without one would break every policy that shares a block with
  a role check. `:system` matches none of them.
  """

  @enforce_keys [:system]
  defstruct [:system, role: :system]

  @type t :: %__MODULE__{system: :hexpm, role: :system}

  @doc "The actor for a verified hex.pm submission."
  @spec hexpm() :: t()
  def hexpm, do: %__MODULE__{system: :hexpm}
end
