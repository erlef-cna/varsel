# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CAPEC.RelatedAttackPattern.Nature do
  @moduledoc false
  use Ash.Type.Enum, values: [:child_of, :parent_of, :can_precede, :can_follow, :peer_of]
end
