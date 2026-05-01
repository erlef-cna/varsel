# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CAPEC.AttackPattern.Likelihood do
  @moduledoc false
  use Ash.Type.Enum, values: [:high, :medium, :low]
end
