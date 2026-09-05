# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.DefaultStatus do
  @moduledoc """
  What the record claims about versions its ranges do not list, rendered as
  `affected[].defaultStatus`.

  `:unknown` is for history the repository does not capture (a squashed import)
  or code never audited that far back. The OTP preset selects it for an
  introduction at the erlang/otp root commit, and it is an ordinary attribute
  from there on.

  `:affected` inverts what the record lists: the ranges name the versions
  carrying the fix, and everything else is vulnerable. It fits a product whose
  releases cannot be enumerated, and a flaw present for as long as the code has
  existed.
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      unaffected: "Every version outside the derived ranges is known safe.",
      unknown: "Nothing is claimed about versions predating the introducing commit.",
      affected: "Every version outside the listed fixed spans is vulnerable."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :affected_package_default_status

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :affected_package_default_status
end
