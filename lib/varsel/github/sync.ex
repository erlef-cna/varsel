# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Sync do
  @moduledoc """
  The options a write to the GitHub App's cache runs with: the caller's own
  actor and authorization, and the context stamp that the write policies of
  `Varsel.GitHub.Installation`, `Varsel.GitHub.InstallationLookup` and
  `Varsel.GitHub.UserInstallation` require next to that actor.
  """

  @stamp %{private: %{installation_sync: true}}

  @doc "The options of `context`, with the stamp added."
  @spec opts(map()) :: keyword()
  def opts(context) do
    context
    |> Ash.Context.to_opts()
    |> Keyword.update(:context, @stamp, &Ash.Helpers.deep_merge_maps(&1, @stamp))
  end
end
