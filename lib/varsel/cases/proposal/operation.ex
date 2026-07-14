# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Operation do
  @moduledoc false
  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      set: "Set one field on the case or on an existing child row.",
      insert: "Add a new child row (the payload is the full row).",
      delete: "Remove an existing child row."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_proposal_operation

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_proposal_operation
end
