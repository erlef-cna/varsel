# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.VersionEvent.Event do
  @moduledoc false
  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      introduced: "The vulnerability was introduced at this boundary.",
      fixed: "The vulnerability was fixed at this boundary (one event per release branch)."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :version_event_kind

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :version_event_kind
end
