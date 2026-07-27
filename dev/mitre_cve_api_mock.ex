# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Dev.MitreCveApiMock do
  @moduledoc """
  In-process stand-in for the MITRE CVE Services API, so the app runs locally
  without MITRE credentials. `config/runtime.exs` wires it in through the
  `plug:` option of the `:mitre_cve_api` config (the same mechanism the test
  suite uses with `Req.Test`) whenever no `MITRE_CVE_API_*` environment
  variables are set — `Varsel.CVE.MitreCveApi` and its callers are untouched.

  Behavior:

    * Reserving draws random `CVE-<year>-9xxxxx` IDs (the high range marks
      them as mock IDs) that don't collide with records already in the DB.
    * Publish/update accepts the CNA container and synthesizes the full CVE
      record with `state: "PUBLISHED"`, `datePublished` and `dateUpdated`
      stamped, held in `:persistent_term` so the follow-up `get` returns it.
      For records published before a BEAM restart, `get` falls back to the
      `cve_json` stored on the record (the dates land there via the publish
      flow), so the nightly sync stays a no-op. An update pushed right after
      a restart re-mints `datePublished` — a known cosmetic dev-only edge.
    * The RESERVED listing pretends the org holds `CVE-<year>-900001` through
      `-900005` (minus any that locally progressed past `:reserved`, matching
      MITRE moving IDs out of that state), so `sync_reserved_from_mitre` seeds
      an empty pool. PUBLISHED and REJECTED listings are empty, making
      `import_from_mitre` and rejection sync no-ops; reject always succeeds.
  """

  @behaviour Plug

  import Plug.Conn

  alias Varsel.CVE.CveRecord

  require Ash.Query

  @mock_id_range 900_000..999_999
  @seed_pool_size 5

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    conn = fetch_query_params(conn)

    case {conn.method, conn.path_info} do
      {"POST", ["cve-id"]} -> reserve(conn)
      {"GET", ["cve-id"]} -> list_ids(conn)
      {"PUT", ["cve-id", cve_id]} -> Req.Test.json(conn, %{"message" => "#{cve_id} rejected"})
      {"POST", ["cve", cve_id, "cna"]} -> put_record(conn, cve_id)
      {"PUT", ["cve", cve_id, "cna"]} -> put_record(conn, cve_id)
      {"GET", ["cve", cve_id]} -> get_record(conn, cve_id)
      _other -> not_found(conn)
    end
  end

  @doc "Removes all records held by the mock. Used by tests."
  @spec reset() :: :ok
  def reset do
    for {{__MODULE__, _cve_id} = key, _record} <- :persistent_term.get() do
      :persistent_term.erase(key)
    end

    :ok
  end

  defp reserve(conn) do
    amount = String.to_integer(conn.query_params["amount"])
    year = conn.query_params["cve_year"]
    org = conn.query_params["short_name"]

    reservations = for cve_id <- generate_ids(year, amount), do: reservation(cve_id, year, org)

    Req.Test.json(conn, %{"cve_ids" => reservations})
  end

  # The org holds the seed reservations "at MITRE" from the start, minus any
  # that locally progressed past :reserved — MITRE moves published/rejected
  # IDs out of the RESERVED state.
  defp list_ids(%{query_params: %{"state" => "RESERVED", "page" => "1"}} = conn) do
    year = Date.utc_today().year
    org = Application.get_env(:varsel, :mitre_cve_api, [])[:org]

    progressed =
      CveRecord
      |> Ash.Query.filter(cve_id in ^seed_ids(year) and state != :reserved)
      |> Ash.read!(authorize?: false, load: [:cve_id])
      |> MapSet.new(& &1.cve_id)

    reservations =
      for cve_id <- seed_ids(year), cve_id not in progressed do
        reservation(cve_id, to_string(year), org)
      end

    Req.Test.json(conn, %{"cve_ids" => reservations})
  end

  defp list_ids(conn), do: Req.Test.json(conn, %{"cve_ids" => []})

  defp seed_ids(year) do
    for n <- 1..@seed_pool_size, do: "CVE-#{year}-#{@mock_id_range.first + n}"
  end

  defp reservation(cve_id, year, org) do
    now = timestamp()

    %{
      "cve_id" => cve_id,
      "cve_year" => year,
      "owning_cna" => org,
      "requested_by" => %{"cna" => org, "user" => "mock@localhost"},
      "reserved" => now,
      "state" => "RESERVED",
      "time" => %{"created" => now, "modified" => now}
    }
  end

  defp generate_ids(year, amount, acc \\ [])
  defp generate_ids(_year, 0, acc), do: acc

  defp generate_ids(year, amount, acc) do
    reserved_for_seeds = seed_ids(year)

    candidates =
      fn -> "CVE-#{year}-#{Enum.random(@mock_id_range)}" end
      |> Stream.repeatedly()
      |> Stream.uniq()
      |> Stream.reject(&(&1 in acc or &1 in reserved_for_seeds))
      |> Enum.take(amount)

    taken =
      CveRecord
      |> Ash.Query.filter(cve_id in ^candidates)
      |> Ash.read!(authorize?: false, load: [:cve_id])
      |> MapSet.new(& &1.cve_id)

    free = Enum.reject(candidates, &(&1 in taken))
    generate_ids(year, amount - length(free), acc ++ free)
  end

  defp put_record(conn, cve_id) do
    {:ok, body, conn} = read_body(conn)
    cna_container = JSON.decode!(body)["cnaContainer"]
    now = timestamp()

    record = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => cve_id,
        "assignerOrgId" => Application.fetch_env!(:varsel, :cna_org_id),
        "assignerShortName" => Application.get_env(:varsel, :cna_short_name, "EEF"),
        "state" => "PUBLISHED",
        "datePublished" => prior_date_published(cve_id) || now,
        "dateUpdated" => now
      },
      "containers" => %{"cna" => cna_container}
    }

    :persistent_term.put({__MODULE__, cve_id}, record)
    Req.Test.json(conn, %{"message" => "#{cve_id} record was successfully submitted."})
  end

  defp get_record(conn, cve_id) do
    case :persistent_term.get({__MODULE__, cve_id}, nil) || db_record(cve_id) do
      nil -> not_found(conn)
      record -> Req.Test.json(conn, record)
    end
  end

  defp prior_date_published(cve_id) do
    case :persistent_term.get({__MODULE__, cve_id}, nil) || db_record(cve_id) do
      %{"cveMetadata" => %{"datePublished" => date}} -> date
      _other -> nil
    end
  end

  # Only records whose cve_json already carries a datePublished exist "at
  # MITRE"; anything else (reserved pool rows, records mid-publish) is a 404,
  # matching the real API for unpublished IDs.
  defp db_record(cve_id) do
    CveRecord
    |> Ash.Query.filter(cve_id == ^cve_id)
    |> Ash.read_one!(authorize?: false)
    |> case do
      %CveRecord{cve_json: %{"cveMetadata" => %{"datePublished" => date}} = cve_json}
      when is_binary(date) ->
        cve_json

      _other ->
        nil
    end
  end

  defp not_found(conn) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(404, JSON.encode!(%{"error" => "NOT_FOUND", "message" => "Record not found."}))
  end

  defp timestamp do
    DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
  end
end
