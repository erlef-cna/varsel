# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.RecordDrift do
  @moduledoc """
  How a published case's record, rendered with the current code and data,
  compares to what is published.
  """
  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      in_sync: "The current render matches the published CVE and OSV records.",
      drifted: "The current render differs from the published CVE or OSV record.",
      blocked: "The current render has publish blockers or fails validation, so it cannot be republished.",
      failed: "The check could not render the case."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_record_drift

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_record_drift
end
