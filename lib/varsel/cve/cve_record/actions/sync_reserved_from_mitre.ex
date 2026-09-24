# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Actions.SyncReservedFromMitre do
  @moduledoc """
  Reconciles the local pool with what MITRE currently holds reserved.

  IDs published externally are picked up by `:import_from_mitre` instead.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE.CveRecord.PoolRow
  alias Varsel.CVE.MitreCveApi

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    opts = Varsel.ObanContext.forward(context)

    MitreCveApi.stream_reserved_ids()
    |> Stream.map(&%{reservation_json: &1})
    |> Stream.chunk_every(100)
    |> Enum.each(fn chunk ->
      Varsel.CVE.reserve_cve_record!(chunk, opts)
    end)

    # Only un-published pool rows are affected; published records are left intact.
    Enum.each(MitreCveApi.stream_rejected_ids(), fn rejected_cve_id ->
      PoolRow.reject(rejected_cve_id, "Rejected externally at MITRE", opts)
    end)

    {:ok, :ok}
  end
end
