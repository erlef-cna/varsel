# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Mock do
  @moduledoc """
  A sign-in provider that asks which role you want instead of asking a
  provider who you are.

  Local development needs an account without a configured OAuth app. Doing that
  outside the auth flow meant a bespoke action, its own policies, its own token
  minting and a synthetic address kept only so repeat sign-ins found the same
  row — all of it parallel to the real thing and none of it exercised by it.

  As a strategy it is simply another provider: `/auth/user/mock` offers the
  three roles, choosing one is the callback, and the account it signs in has an
  ordinary identity row. Everything downstream — resolution, linking,
  unlinking, the account page — treats it like GitHub or Hex.pm, which also
  means those paths get exercised in development.

  Lives under `dev/`, compiled only for `:dev` and `:test`.
  """

  use AshAuthentication.Strategy.Custom, entity: __MODULE__.Dsl.dsl()

  @roles [
    {"poc", "POC", :poc},
    {"supporter", "Supporter", :supporter},
    {"none", "No role", nil}
  ]

  @doc "The roles offered, as `{uid, label, role}`."
  @spec roles() :: [{String.t(), String.t(), atom | nil}]
  def roles, do: @roles

  @doc "The role an offered uid stands for, or `:error`."
  @spec role_for(String.t()) :: {:ok, atom | nil} | :error
  def role_for(uid) do
    case Enum.find(@roles, &(elem(&1, 0) == uid)) do
      nil -> :error
      {_uid, _label, role} -> {:ok, role}
    end
  end

  defstruct name: :mock,
            resource: nil,
            provider: :mock,
            strategy_module: __MODULE__,
            register_action_name: :register_with_mock,
            identity_resource: nil,
            identity_relationship_name: :identities,
            identity_relationship_user_id_attribute: :user_id,
            registration_enabled?: true,
            icon: :mock,
            __spark_metadata__: nil

  @type t :: %__MODULE__{}

  defdelegate transform(strategy, dsl_state), to: __MODULE__.Transformer
  def verify(_strategy, _dsl_state), do: :ok
end
