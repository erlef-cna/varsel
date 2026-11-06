# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Signals do
  @moduledoc """
  The signals that cases emit for other parts of Varsel to react to.
  """

  use Ash.Signals

  signals do
    signal :report_submitted do
      description "A vulnerability report arrived, from a reporter here or from hex.pm, and opened a case."
      argument :case_id, :uuid, allow_nil?: false

      argument :actor_id, :uuid, description: "The user who submitted the report, when a user did."
    end

    signal :case_closed do
      description "A case reached its terminal state and will result in no published CVE."
      argument :case_id, :uuid, allow_nil?: false
    end

    signal :case_merged do
      description "A case not accepted yet was merged into another case that covers the same finding."
      argument :case_id, :uuid, allow_nil?: false, description: "The case that was merged."
      argument :into_case_id, :uuid, allow_nil?: false, description: "The case that takes over."
    end

    signal :proposal_target_destroyed do
      description "A row that proposals address was deleted."
      argument :target_id, :uuid, allow_nil?: false

      argument :driving_proposal_id, :uuid,
        description: "The accepted :delete proposal that drove the destroy, which is not orphaned."
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

    signal :package_facts_changed do
      description "A channel or boundary fact of an affected package was written or removed."
      argument :affected_package_id, :uuid, allow_nil?: false
    end

    signal :review_requested do
      description "A drafted case was marked ready for POC review."
      argument :case_id, :uuid, allow_nil?: false
      argument :actor_id, :uuid, description: "The user who asked for review, when a user did."
    end

    signal :case_published do
      description "A case's CVE record reached MITRE and the case is published."
      argument :case_id, :uuid, allow_nil?: false
      argument :actor_id, :uuid, description: "The user who marked it published, when a user did."
    end

    signal :comment_posted do
      description "A comment was written on a case, here or on its linked GitHub advisory."
      argument :case_id, :uuid, allow_nil?: false

      argument :actor_id, :uuid, description: "The user who wrote the comment here, when a user did."
    end

    signal :proposal_opened do
      description "A proposal was opened on a case."
      argument :case_id, :uuid, allow_nil?: false
      argument :actor_id, :uuid, description: "The user who proposed, when a user did."
    end

    signal :case_assigned do
      description "A user was granted access to a case they did not have."
      argument :case_id, :uuid, allow_nil?: false
      argument :user_id, :uuid, allow_nil?: false
      argument :actor_id, :uuid, description: "The user who granted the access, when a user did."
    end
  end
end
