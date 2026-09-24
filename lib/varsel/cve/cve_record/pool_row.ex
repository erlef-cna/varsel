# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.PoolRow do
  @moduledoc """
  Pool-row writes shared by the MITRE sync actions of `Varsel.CVE.CveRecord`.
  """

  alias Varsel.CVE.CveRecord

  require Ash.Query

  @doc """
  Marks the pool row for `cve_id` rejected. Published records are left intact.
  """
  @spec reject(String.t(), String.t(), keyword()) :: :ok
  def reject(cve_id, reason, opts) do
    CveRecord
    |> Ash.Query.filter(cve_id == ^cve_id and state in [:reserved, :withheld])
    |> Varsel.CVE.mark_cve_record_rejected!(
      %{rejection_reason: reason},
      Keyword.put(opts, :bulk_options,
        return_errors?: true,
        strategy: :stream,
        allow_stream_with: :full_read
      )
    )

    :ok
  end
end
