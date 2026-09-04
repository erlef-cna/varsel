# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Repo.Migrations.ReleaseParkedCveIds do
  @moduledoc """
  Returns the drafted CVE IDs of closed cases to the pool. Closing a case now
  releases its ID unless the ID is rejected, so the cases closed before that
  rule catch up here.
  """

  use Ecto.Migration

  def up do
    execute("""
    WITH parked AS (
      SELECT c.id AS case_id, c.cve_record_id
      FROM cases c
      JOIN cve_records r ON r.id = c.cve_record_id
      WHERE c.state = 'closed' AND r.state = 'draft'
    ),
    unlinked AS (
      UPDATE cases
      SET cve_record_id = NULL
      WHERE id IN (SELECT case_id FROM parked)
    )
    UPDATE cve_records
    SET state = 'reserved', version = version + 1, updated_at = now()
    WHERE id IN (SELECT cve_record_id FROM parked)
    """)
  end

  def down do
    :ok
  end
end
