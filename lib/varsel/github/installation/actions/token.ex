# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation.Actions.Token do
  @moduledoc """
  Runs `Varsel.GitHub.Installation`'s `:token` action as the caller.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.GitHub.Installation.Mint
  alias Varsel.GitHub.Sync

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    Mint.token(input.arguments.installation_id, Sync.opts(context))
  end
end
