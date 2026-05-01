# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CWE.Weakness.Abstraction do
  @moduledoc false
  use Ash.Type.Enum, values: [:pillar, :class, :base, :variant, :compound]
end
