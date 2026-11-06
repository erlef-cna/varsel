# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.Signals do
  @moduledoc """
  The signals that CVE intake emits for other parts of Varsel to react to.
  """

  use Ash.Signals

  signals do
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
  end
end
