# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.DefaultStatus do
  @moduledoc """
  Rendered as `affected[].defaultStatus`: the status of any version not
  matched by the rendered `versions[]` entries.

  EEF practice: `:unaffected` for bounded ranges (the default), `:unknown`
  when unpatched release lines may exist (e.g. Erlang/OTP), `:affected` when
  no fix will ship.
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum, values: [:affected, :unaffected, :unknown]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :affected_package_default_status

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :affected_package_default_status
end
