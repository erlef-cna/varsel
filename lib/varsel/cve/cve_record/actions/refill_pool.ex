# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Actions.RefillPool do
  @moduledoc """
  Reserves CVE IDs at MITRE until the open pool reaches its minimum size.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.MitreCveApi

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    opts = Varsel.ObanContext.forward(context)
    skip_on_empty = input.arguments[:skip_on_empty]

    if skip_on_empty and Ash.count!(CveRecord, opts) == 0 do
      {:ok, :ok}
    else
      refill(input.arguments[:year] || Date.utc_today().year, opts)
    end
  end

  defp refill(year, opts) do
    min_size = Application.get_env(:varsel, :cve_pool_min_size, 10)

    open_count =
      year
      |> Varsel.CVE.query_to_available_cve_records(opts)
      |> Ash.count!(opts)

    if open_count < min_size do
      reserve(year, min_size - open_count, opts)
    end

    {:ok, :ok}
  end

  defp reserve(year, amount, opts) do
    case MitreCveApi.reserve(year, amount) do
      {:ok, reservation_jsons} ->
        inputs = Enum.map(reservation_jsons, &%{reservation_json: &1})

        Varsel.CVE.reserve_cve_record!(inputs, opts)

      {:error, reason} ->
        raise "Failed to reserve CVE IDs from MITRE: #{reason}"
    end
  end
end
