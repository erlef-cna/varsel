# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.State do
  @moduledoc """
  The states GitHub gives a repository security advisory, plus `:unknown` for
  a state this code does not know.
  """

  use Ash.Type.Enum,
    values: [
      triage: "Reported privately. The maintainers have not taken it up yet.",
      draft: "Being written. Visible to its collaborators only.",
      published: "Public on GitHub.",
      closed: "Closed without publication.",
      withdrawn: "Published, then withdrawn.",
      unknown: "A state GitHub added after this was written."
    ]
end
