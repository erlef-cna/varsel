# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.EmailMode do
  @moduledoc """
  How a user wants their requested notification emails delivered.
  """

  use Ash.Type.Enum,
    values: [
      immediate: [label: "Immediately", description: "One email per notification, as it happens."],
      daily_digest: [
        label: "Daily digest",
        description: "One email per day listing what is unread."
      ]
    ]
end
