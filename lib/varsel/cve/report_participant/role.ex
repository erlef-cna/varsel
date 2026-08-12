# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.ReportParticipant.Role do
  @moduledoc """
  How someone named on a report relates to it.
  """

  use Ash.Type.Enum,
    values: [
      reporter: "Submitted the report.",
      maintainer: "Maintains the reported package."
    ]
end
