# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.SeedPrimaryEmail do
  @moduledoc """
  Writes a provider-reported address as the account's primary email, but only
  when the account does not have one yet.

  Signing in again must never re-point the primary email: which address an
  account is reachable at is the user's decision (`:set_primary_email`), not
  the most recent provider's. Upserts complicate this — on a conflict the
  changeset holds the *incoming* values, not the stored row — so the guard is
  expressed as an atomic update that leaves a non-null email alone.
  """

  use Ash.Resource.Change

  @doc """
  Seeds `email` as the primary address unless one is already set.
  """
  @spec seed(Ash.Changeset.t(), String.t() | nil) :: Ash.Changeset.t()
  def seed(changeset, nil), do: changeset

  def seed(changeset, email) do
    changeset
    |> Ash.Changeset.force_change_attribute(:email, email)
    |> Ash.Changeset.atomic_update(:email, expr(if is_nil(email), do: ^email, else: email))
  end

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    seed(changeset, Ash.Changeset.get_argument(changeset, :user_info)["email"])
  end
end
