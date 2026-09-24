# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.OsvRecord.Actions.CreateMissing do
  @moduledoc """
  Creates OSV records for published CVE records that have none yet.

  Failures are isolated per record: the run collects every error and raises at
  the end, so one bad record does not stop the others and Oban retries the
  whole sweep.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.OsvRecord

  require Ash.Query

  @impl Ash.Resource.Actions.Implementation
  def run(_input, _opts, context) do
    opts = Varsel.ObanContext.forward(context)

    errors =
      CveRecord
      |> Ash.Query.filter(state == :published and not exists(osv_record, true))
      |> Ash.read!(opts)
      |> Enum.flat_map(&create_for(&1, opts))

    if errors == [] do
      {:ok, :ok}
    else
      raise "Failed to create OSV records: #{inspect(errors)}"
    end
  end

  defp create_for(cve_record, opts) do
    case OsvRecord.derive(cve_record) do
      {:ok, osv, content_hash} ->
        now = DateTime.utc_now()

        Ash.create!(
          OsvRecord,
          %{
            osv_id: osv["id"],
            cve_record_id: cve_record.id,
            osv_json: OsvRecord.stamp_modified(osv, now),
            content_hash: content_hash,
            modified_at: now,
            synced_at: now
          },
          Keyword.put(opts, :action, :create)
        )

        []

      {:skip, _reason} ->
        []

      {:error, reason} ->
        [{get_in(cve_record.cve_json, ["cveMetadata", "cveId"]), reason}]
    end
  end
end
