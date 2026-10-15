# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation.RepositorySelection do
  @moduledoc false

  use Ash.Type.Enum,
    values: [
      all: "The installation covers every repository of its account, including repositories created later.",
      selected: "The installation covers only the repositories that the account owner selected."
    ]
end
