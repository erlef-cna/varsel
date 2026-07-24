# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.StampDerivationCache do
  @moduledoc """
  Stamps `derivation_cached_at` and `updated_at` with the same instant when the
  derivation cache is written, so a fresh cache never reads as older than the
  package row it lives on (the freshness check compares the two — see
  `Varsel.Cases.DerivationFreshness`).
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    now = DateTime.utc_now()

    changeset
    |> Ash.Changeset.force_change_attribute(:derivation_cached_at, now)
    |> Ash.Changeset.force_change_attribute(:updated_at, now)
  end
end
