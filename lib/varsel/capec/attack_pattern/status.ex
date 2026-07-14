# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.AttackPattern.Status do
  @moduledoc false
  use Ash.Type.Enum, values: [:draft, :stable, :deprecated, :obsolete, :usable]
end
