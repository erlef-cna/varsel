# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Hammer do
  @moduledoc """
  Rate limiting backend for `AshRateLimiter`, backed by a node-local ETS table.
  """

  use Hammer, backend: :ets
end
