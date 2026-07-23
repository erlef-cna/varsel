# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.RefreshDerivation do
  @moduledoc """
  Recomputes and caches the derivation result of every affected package of
  the case. Runs after the (otherwise empty) update commits.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Derivation

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    actor = context.actor

    Ash.Changeset.after_action(changeset, fn _changeset, case_record ->
      loads = [affected_packages: [:channels, :version_events]]
      loaded = Ash.load!(case_record, loads, actor: actor)

      Enum.each(loaded.affected_packages, &recompute/1)

      {:ok, case_record}
    end)
  end

  # Derives fresh ranges and caches them on the package. This runs as a
  # side effect of the already policy-gated refresh, not a user edit, so the
  # cache write bypasses authorization.
  defp recompute(package) do
    {:ok, derivation} = Derivation.derive(package)

    package
    # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
    |> Ash.Changeset.for_update(:store_derivation, %{derivation_cache: derivation}, authorize?: false)
    |> Ash.update!()
  end
end
