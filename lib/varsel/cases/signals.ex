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

    signal :proposal_accepted do
      description "A proposal was accepted and applied to its target."
      argument :proposal_id, :uuid, allow_nil?: false
      argument :case_id, :uuid, allow_nil?: false
      argument :operation, Varsel.Cases.Proposal.Operation, allow_nil?: false
      argument :target, Varsel.Cases.Proposal.Target, allow_nil?: false
      argument :target_id, :uuid
      argument :field_name, :string
    end
  end
end
