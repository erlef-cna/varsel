# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Service do
  @moduledoc """
  The actor an internal system runs as.

  A system is an identity like any other, so it is passed to actions as one
  and checked by policies the way a user is. Each system's actor is built
  only by the subsystem it names, so holding it means that subsystem is the
  caller.

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
  @type system() ::
          system_hexpm_intake()
          | system_identity_claim()
          | system_notifier()
          | system_release_console()

  @typedoc """
  hex.pm's package-report intake, verified by `VarselWeb.Plugs.HexServiceAuth`.
  """
  @type system_hexpm_intake() :: :hexpm_intake

  @typedoc """
  Connects provider handles to accounts once the provider vouches for them:
  claiming report participants and case invites on sign-in, and pointing a
  new participant at the account already holding its handle.
  """
  @type system_identity_claim() :: :identity_claim

  @typedoc """
  Post-commit Ash notifiers loading a related row to decide which lifecycle
  trigger to fire.
  """
  @type system_notifier() :: :notifier

  @typedoc """
  Release tasks in `Varsel.Release`. What authorizes them is shell access to
  a fully configured server: someone who has that can already reach the
  database directly.
  """
  @type system_release_console() :: :release_console

  @type t() :: %__MODULE__{system: system(), role: :system}

  @doc "The actor for a verified hex.pm submission."
  @spec hexpm_intake() :: t()
  def hexpm_intake, do: %__MODULE__{system: :hexpm_intake}

  @doc "The actor the sign-in identity claim runs as."
  @spec identity_claim() :: t()
  def identity_claim, do: %__MODULE__{system: :identity_claim}

  @doc "The actor a post-commit notifier loads related rows as."
  @spec notifier() :: t()
  def notifier, do: %__MODULE__{system: :notifier}

  @doc "The actor a release task runs as."
  @spec release_console() :: t()
  def release_console, do: %__MODULE__{system: :release_console}
end
