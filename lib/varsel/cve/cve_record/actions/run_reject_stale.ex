# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Actions.RunRejectStale do
  @moduledoc """
  Rejects every open prior-year reservation at MITRE. Runs February 1st.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE.CveRecord

  require Ash.Query

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    opts = Varsel.ObanContext.forward(context)
    current_year = Date.utc_today().year
    current_year_start = DateTime.new!(Date.new!(current_year, 1, 1), ~T[00:00:00])

    CveRecord
    |> Ash.Query.filter(state == :reserved and reserved_at < ^current_year_start)
    |> Varsel.CVE.reject_cve_record!(
      %{rejection_reason: "Stale prior-year reservation"},
      Keyword.put(opts, :bulk_options,
        return_errors?: true,
        strategy: :stream,
        allow_stream_with: :full_read
      )
    )

    {:ok, :ok}
  end
end
