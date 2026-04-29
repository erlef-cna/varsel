# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.CveReservation.OkResult do
  @moduledoc false
  use Ash.Type.Enum, values: [:ok]
end

defmodule CveManagement.CVE.CveReservation do
  @moduledoc """
  Represents a CVE ID reserved from MITRE that is available for assignment to a case.

  ## Lifecycle

  The reservation lifecycle is encoded purely in `case_id`:

  - `case_id IS NULL` — open/available in the pool
  - `case_id IS NOT NULL` — assigned to a case awaiting publication

  When the associated CVE record is published, or when a stale unassigned reservation is
  rejected at MITRE, the row is simply deleted — no tombstone is kept.

  ## Stored data

  `reservation_json` holds the raw reservation object as returned by the MITRE CVE Services
  API (same pattern as `CveRecord` stores `cve_json`). The fields `cve_id`, `reserved_at`,
  and `year` are derived from it via calculated fields backed by PostgreSQL fragments.

  ## Background jobs

  - `top_up_pool` (every 15 min) — reserves more IDs from MITRE if the open pool for the
    current year falls below `cve_pool_min_size`.
  - `sync_reserved_from_mitre` (daily 03:00) — upserts any IDs reserved outside this app and
    destroys any that MITRE has already rejected.
  - `reject_stale` (Feb 1st 04:00) — rejects prior-year unassigned IDs at MITRE and removes
    them locally.
  """

  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.CVE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban]

  import Ash.Expr

  alias CveManagement.CVE.CveReservation.OkResult
  alias CveManagement.CVE.MitreCveApi

  require Ash.Query

  postgres do
    table "cve_reservations"
    repo CveManagement.Repo

    calculations_to_sql cve_id: "reservation_json->>'cve_id'",
                        reserved_at: "(reservation_json->>'reserved')::timestamptz",
                        year: "(reservation_json->>'cve_year')::integer"
  end

  oban do
    scheduled_actions do
      schedule :top_up_pool, "*/15 * * * *",
        action: :top_up_pool,
        worker_module_name: CveManagement.CVE.CveReservation.TopUpPoolWorker,
        queue: :cve_pool,
        max_attempts: 3

      schedule :sync_reserved_from_mitre, "0 3 * * *",
        action: :sync_reserved_from_mitre,
        worker_module_name: CveManagement.CVE.CveReservation.SyncReservedFromMitreWorker,
        queue: :cve_pool,
        max_attempts: 3

      schedule :reject_stale, "0 4 1 2 *",
        action: :run_reject_stale,
        worker_module_name: CveManagement.CVE.CveReservation.RejectStaleWorker,
        queue: :cve_pool,
        max_attempts: 3
    end
  end

  actions do
    defaults [:destroy]

    read :read do
      primary? true
      pagination keyset?: true, required?: false
    end

    read :available do
      description "Returns open (unassigned) reservations for a given year."

      argument :year, :integer, allow_nil?: false

      filter expr(is_nil(case_id) and year == ^arg(:year))
    end

    create :reserve do
      description "Creates a reservation from a raw MITRE API reservation object."
      accept [:reservation_json]

      upsert? true
      upsert_identity :unique_cve_id
      upsert_fields [:reservation_json]
    end

    update :assign do
      description "Assigns this reservation to a case."
      accept [:case_id]
    end

    action :top_up_pool, OkResult do
      description """
      Ensures the open pool for the given year meets the configured minimum size.
      Defaults to the current year. Reserves additional IDs from MITRE if needed.
      """

      argument :year, :integer do
        allow_nil? true
        description "The CVE year to top up. Defaults to the current year."
      end

      run fn input, _context ->
        year = input.arguments[:year] || Date.utc_today().year
        min_size = Application.get_env(:cve_management, :cve_pool_min_size, 10)

        open_count =
          CveManagement.CVE.CveReservation
          |> Ash.Query.for_read(:available, %{year: year}, authorize?: false)
          |> Ash.count!(authorize?: false)

        if open_count < min_size do
          amount = min_size - open_count

          case MitreCveApi.reserve(year, amount) do
            {:ok, reservation_jsons} ->
              inputs = Enum.map(reservation_jsons, &%{reservation_json: &1})

              Ash.bulk_create!(inputs, __MODULE__, :reserve, authorize?: false)

            {:error, reason} ->
              raise "Failed to reserve CVE IDs from MITRE: #{reason}"
          end
        end

        {:ok, :ok}
      end
    end

    action :sync_reserved_from_mitre, OkResult do
      description """
      Upserts IDs currently RESERVED at MITRE (catching external reservations) and
      destroys any local rows whose IDs MITRE has already rejected or published.
      """

      run fn _input, _context ->
        # 1. Upsert all RESERVED IDs from MITRE
        MitreCveApi.stream_reserved_ids()
        |> Stream.map(&%{reservation_json: &1})
        |> Stream.chunk_every(100)
        |> Enum.each(fn chunk ->
          Ash.bulk_create!(chunk, __MODULE__, :reserve, authorize?: false)
        end)

        # 2. Destroy local rows for IDs that MITRE has rejected externally
        Enum.each(MitreCveApi.stream_rejected_ids(), fn rejected_cve_id ->
          __MODULE__
          |> Ash.Query.filter(cve_id: rejected_cve_id)
          |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false, return_errors?: true)
        end)

        # 3. Destroy local rows for IDs that MITRE has published
        Enum.each(MitreCveApi.stream_ids(), fn published_cve_id ->
          __MODULE__
          |> Ash.Query.filter(cve_id: published_cve_id)
          |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false, return_errors?: true)
        end)

        {:ok, :ok}
      end
    end

    destroy :reject_stale do
      description """
      Rejects a single reservation at MITRE and removes it locally.
      Called via bulk_destroy! by the :run_reject_stale scheduled action.
      """

      require_atomic? false

      change before_action(fn changeset, _context ->
               reservation = changeset.data
               {:ok, _} = MitreCveApi.reject(reservation.cve_id)
               changeset
             end)
    end

    action :run_reject_stale, OkResult do
      description """
      Scheduled entry point for stale rejection. Runs Feb 1st each year.
      Bulk-destroys all open prior-year reservations via :reject_stale.
      """

      run fn _input, _context ->
        current_year = Date.utc_today().year
        current_year_start = DateTime.new!(Date.new!(current_year, 1, 1), ~T[00:00:00])

        __MODULE__
        |> Ash.Query.filter(expr(is_nil(case_id) and reserved_at < ^current_year_start))
        |> Ash.Query.load(:cve_id)
        |> Ash.bulk_destroy!(:reject_stale, %{},
          authorize?: false,
          return_errors?: true,
          strategy: :stream,
          allow_stream_with: :full_read
        )

        {:ok, :ok}
      end
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :reservation_json, :map do
      allow_nil? false
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, CveManagement.Cases.Case do
      public? true
      allow_nil? true
    end
  end

  calculations do
    calculate :cve_id, :string, expr(fragment("?->>'cve_id'", reservation_json)) do
      public? true
    end

    calculate :reserved_at,
              :utc_datetime,
              expr(fragment("(?->>'reserved')::timestamptz", reservation_json)) do
      public? true
    end

    calculate :year,
              :integer,
              expr(fragment("(?->>'cve_year')::integer", reservation_json)) do
      public? true
    end
  end

  identities do
    identity :unique_cve_id, [:cve_id]
  end
end
