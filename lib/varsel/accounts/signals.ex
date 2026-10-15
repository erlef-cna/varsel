# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Signals do
  @moduledoc """
  The signals that accounts emit for other parts of Varsel to react to.
  """

  use Ash.Signals

  signals do
    signal :github_identity_linked do
      description "A GitHub sign-in or provider link wrote the account's GitHub identity."
      argument :user_id, :uuid, allow_nil?: false
    end
  end
end
