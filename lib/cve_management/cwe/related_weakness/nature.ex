# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CWE.RelatedWeakness.Nature do
  @moduledoc false
  use Ash.Type.Enum,
    values: [
      :child_of,
      :parent_of,
      :peer_of,
      :can_precede,
      :can_follow,
      :required_by,
      :requires,
      :can_also_be,
      :starts_with
    ]
end
