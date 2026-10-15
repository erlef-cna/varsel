# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation.Kind do
  @moduledoc false

  use Ash.Type.Enum,
    values: [
      organization: "The App is installed on an organization account (GitHub's target type `Organization`).",
      user: "The App is installed on a personal account (GitHub's target type `User`)."
    ]
end
