# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInvite.Role do
  @moduledoc """
  What an invited person is to the case. It decides which invite email they
  get: a maintainer's states the CNA's non-response policy.
  """

  use Ash.Type.Enum,
    values: [
      maintainer: "Maintains an affected package, and is asked to fix the vulnerability.",
      other: "Anyone else the case needs, such as a reporter or a collaborator."
    ]
end
