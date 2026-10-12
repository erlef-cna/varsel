# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Role do
  @moduledoc false
  @behaviour AshGraphql.Type

  use Ash.Type.Enum, values: [:poc, :supporter]

  @doc "The name a role is shown under. Having no role has no name."
  @spec label(t() | nil) :: String.t() | nil
  def label(:poc), do: "POC"
  def label(:supporter), do: "Supporter"
  def label(nil), do: nil

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :user_role

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :user_role
end
