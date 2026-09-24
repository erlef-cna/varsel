# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Actions.ImportFromMitre do
  @moduledoc """
  Imports every published CVE record MITRE holds.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.MitreCveApi

  require Ash.Query
  require Logger

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    opts = Varsel.ObanContext.forward(context)

    protected_ids = protected_ids(opts)

    MitreCveApi.stream_ids()
    |> Stream.reject(&skip?(&1, protected_ids))
    |> Enum.map(fn cve_id ->
      {:ok, cve_json} = MitreCveApi.get(cve_id)
      %{cve_json: cve_json}
    end)
    |> Enum.chunk_every(100)
    |> Enum.each(fn chunk ->
      Varsel.CVE.import_cve_record!(chunk, opts)
    end)

    {:ok, :ok}
  end

  # Warning and GET-saving only: a row that enters a protected state after this
  # snapshot is still skipped (silently) by the :import upsert_condition, which
  # stays the enforcement.
  defp protected_ids(opts) do
    CveRecord
    |> Ash.Query.filter(state not in [:reserved, :withheld, :published])
    |> Ash.Query.load(:cve_id)
    |> Ash.read!(opts)
    |> MapSet.new(& &1.cve_id)
  end

  defp skip?(cve_id, protected_ids) do
    skip? = MapSet.member?(protected_ids, cve_id)

    if skip? do
      Logger.warning("Skipped MITRE import of #{cve_id}: the local record is none of :reserved, :withheld or :published")
    end

    skip?
  end
end
