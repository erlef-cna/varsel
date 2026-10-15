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

    signal :identity_linked do
      description """
      A provider vouched for a handle on an account, at a first sign-in or a
      later provider link. What was waiting on that handle is now theirs.
      """

      argument :user_id, :uuid, allow_nil?: false
      argument :strategy, :string, allow_nil?: false
      argument :username, :ci_string, allow_nil?: false
    end
  end
end
