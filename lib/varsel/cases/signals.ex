# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Signals do
  @moduledoc """
  The signals that cases emit for other parts of Varsel to react to.
  """

  use Ash.Signals

  signals do
    signal :case_closed do
      description "A case reached its terminal state and will result in no published CVE."
      argument :case_id, :uuid, allow_nil?: false
    end
  end
end
