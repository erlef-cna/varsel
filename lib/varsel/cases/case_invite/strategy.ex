# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInvite.Strategy do
  @moduledoc """
  The provider an invite names someone by.

  The values match `Varsel.Accounts.UserIdentity`'s `strategy`, which is what
  an invite is matched against.
  """

  use Ash.Type.Enum,
    values: [
      github: "A GitHub account, by login.",
      hex: "A hex.pm account, by username."
    ]
end
