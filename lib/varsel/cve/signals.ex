# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.Signals do
  @moduledoc """
  The signals that CVE intake emits for other parts of Varsel to react to.
  """

  use Ash.Signals

  signals do
    signal :report_submitted do
      description "A vulnerability report arrived, from a reporter here or from hex.pm."
      argument :report_id, :uuid, allow_nil?: false

      argument :actor_id, :uuid, description: "The user who submitted the report, when a user did."
    end

    signal :cve_record_assigned do
      description "A CVE ID left the open pool for a case."
      argument :cve_record_id, :uuid, allow_nil?: false
    end

    signal :cve_record_published do
      description "A CVE record was written as published: published, updated, imported or synced from MITRE."
      argument :cve_record_id, :uuid, allow_nil?: false
    end

    signal :cve_record_rejected do
      description "A CVE ID was rejected and is burned."
      argument :cve_record_id, :uuid, allow_nil?: false
    end

    signal :report_resolved do
      description """
      A report reached a terminal state: accepted onto a case, rejected, or
      withdrawn by its reporter. What the report no longer needs can go.
      """

      argument :report_id, :uuid, allow_nil?: false
    end
  end
end
