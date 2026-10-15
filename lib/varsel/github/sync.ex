# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Sync do
  @moduledoc """
  The options a write to the GitHub App's installations runs with: the
  enclosing action's scope, forwarded by `Varsel.ObanContext.forward/1`,
  and the context stamp that the write policies of
  `Varsel.GitHub.Installation`, `Varsel.GitHub.InstallationRepository` and
  `Varsel.GitHub.UserInstallation` require next to an actor rule or the
  AshOban bypass.
  """

  @stamp %{private: %{github_sync: true}}

  @doc "The options of `context`, with the stamp added."
  @spec opts(map()) :: keyword()
  def opts(context) do
    context
    |> Varsel.ObanContext.forward()
    |> Keyword.update(:context, @stamp, &Ash.Helpers.deep_merge_maps(&1, @stamp))
  end
end
