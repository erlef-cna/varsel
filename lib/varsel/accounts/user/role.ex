# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Role do
  @moduledoc false
  @behaviour AshGraphql.Type

  use Ash.Type.Enum, values: [:poc, :supporter]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :user_role

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :user_role
end
