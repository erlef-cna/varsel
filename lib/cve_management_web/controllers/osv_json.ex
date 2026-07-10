# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.OsvJSON do
  def index(%{records: records}) do
    Enum.map(records, &%{id: &1.osv_id, modified: DateTime.to_iso8601(&1.modified_at)})
  end
end
