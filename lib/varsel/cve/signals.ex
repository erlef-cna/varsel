# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.Signals do
  @moduledoc """
  The signals that CVE intake emits for other parts of Varsel to react to.
  """

  use Ash.Signals

  signals do
    signal :report_resolved do
      description """
      A report reached a terminal state: accepted onto a case, rejected, or
      withdrawn by its reporter. What the report no longer needs can go.
      """

      argument :report_id, :uuid, allow_nil?: false
    end
  end
end
