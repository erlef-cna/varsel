# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.RefreshDerivation do
  @moduledoc """
  Recomputes and caches the derivation result of every affected package of
  the case. Runs after the (otherwise empty) update commits.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Publication

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    actor = context.actor

    Ash.Changeset.after_action(changeset, fn _changeset, case_record ->
      loads = [affected_packages: [:channels, :version_events]]
      loaded = Ash.load!(case_record, loads, actor: actor)

      Enum.each(loaded.affected_packages, &Publication.refresh_package(&1, actor: actor))

      {:ok, case_record}
    end)
  end
end
