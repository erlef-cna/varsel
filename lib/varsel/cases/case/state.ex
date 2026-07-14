# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.State do
  @moduledoc false
  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      draft: "Being worked on; content is editable and proposals can be accepted.",
      review: "Ready for POC review; content is still editable.",
      approved: "POC signed off; content is frozen until published or reopened.",
      publishing: "Handed to the CVE record publish machinery; awaiting MITRE.",
      published: "Live at MITRE. Amendments require reopening the case.",
      closed: "Terminal: the case will not (or no longer) result in a published CVE."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_state

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_state
end
