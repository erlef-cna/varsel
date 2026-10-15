# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequest.Operation do
  @moduledoc """
  What a manual GitHub request does, and so how its answer is recorded.
  """

  use Ash.Type.Enum,
    values: [
      read: "Reads the advisory: to link it, refresh the link, or refresh and pull fields.",
      push: "Writes fields of the case onto the linked advisory.",
      report: "Opens a draft advisory or a private report on a repository."
    ]
end
