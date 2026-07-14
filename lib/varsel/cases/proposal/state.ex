# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.State do
  @moduledoc false
  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      open: "Awaiting resolution.",
      accepted: "Accepted; the proposed change was applied to the case.",
      declined: "Declined by a reviewer.",
      superseded: "Made obsolete by an accepted competing proposal, a deleted target row, or a closed case.",
      withdrawn: "Retracted by its author."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_proposal_state

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_proposal_state
end
