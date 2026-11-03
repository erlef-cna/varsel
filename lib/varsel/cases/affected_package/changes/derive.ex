# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.Changes.Derive do
  @moduledoc """
  Derives the package from its current facts and caches the result.

  The derivation walks git repositories, so it runs before the transaction.
  `derivation_cached_at` is the instant the facts were read, not the instant
  the result was written. A fact written while the derivation ran is newer
  than that instant, so the package reads `:outdated` and the `:derive`
  trigger runs again. `updated_at` moves up to the same instant only when no
  newer write landed, so the cache never reads as older than its own row.
  """

  use Ash.Resource.Change

  import Ash.Expr

  alias Varsel.Cases.Derivation

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_transaction(changeset, fn changeset ->
      read_at = DateTime.utc_now()

      package =
        Ash.load!(
          changeset.data,
          [:channels, :version_events],
          Varsel.ObanContext.forward(context)
        )

      {:ok, derivation} = Derivation.derive(package)

      changeset
      |> Ash.Changeset.force_change_attribute(:derivation_cache, derivation)
      |> Ash.Changeset.force_change_attribute(:derivation_cached_at, read_at)
      |> Ash.Changeset.atomic_update(
        :updated_at,
        expr(fragment("GREATEST(?, ?)", updated_at, ^read_at))
      )
    end)
  end
end
