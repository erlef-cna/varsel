# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Discovery do
  @moduledoc """
  How the vulnerability was discovered, rendered as `source.discovery`
  (upcased) in the CNA container.
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum, values: [:external, :internal, :unknown]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_discovery

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_discovery
end
