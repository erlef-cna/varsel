# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.RefreshDerivation do
  @moduledoc """
  Recomputes and caches the derivation result of every affected package of
  the case. Runs after the (otherwise empty) update commits. With the
  `refresh` argument set, each package repository's cached git state is
  brought up to date with the remote first.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Derivation
  alias Varsel.Cases.Derivation.GitBackend

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    actor = context.actor
    refresh? = Ash.Changeset.get_argument(changeset, :refresh)

    Ash.Changeset.after_action(changeset, fn _changeset, case_record ->
      loads = [affected_packages: [:channels, :version_events]]
      loaded = Ash.load!(case_record, loads, actor: actor)

      if refresh?, do: refresh_repos(loaded.affected_packages)

      Enum.each(loaded.affected_packages, &recompute(&1, context))

      {:ok, case_record}
    end)
  end

  defp refresh_repos(packages) do
    packages
    |> Enum.map(& &1.repo_url)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.each(&GitBackend.refresh/1)
  end

  @stamp %{private: %{refresh_derivation?: true}}

  defp recompute(package, context) do
    opts =
      context
      |> Ash.Context.to_opts()
      |> Keyword.update(:context, @stamp, &Ash.Helpers.deep_merge_maps(&1, @stamp))

    {:ok, derivation} = Derivation.derive(package)

    package
    |> Ash.Changeset.for_update(:store_derivation, %{derivation_cache: derivation}, opts)
    |> Ash.update!()
  end
end
