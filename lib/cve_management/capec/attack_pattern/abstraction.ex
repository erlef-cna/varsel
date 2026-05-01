# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CAPEC.AttackPattern.Abstraction do
  @moduledoc false
  use Ash.Type.Enum, values: [:meta, :standard, :detailed]
end
