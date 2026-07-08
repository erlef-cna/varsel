# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.CveRecordTest do
  use CveManagement.DataCase, async: false

  alias CveManagement.CVE.CveRecord
  alias CveManagement.CVE.MitreCveApi

  @year Date.utc_today().year
  @cve_id "CVE-2025-12345"

  @cna_container %{
    "title" => "Test vulnerability",
    "descriptions" => [%{"lang" => "en", "value" => "A test vulnerability."}],
    "affected" => [],
    "references" => []
  }

  @updated_cna_container %{
    "title" => "Updated vulnerability",
    "descriptions" => [%{"lang" => "en", "value" => "An updated description."}],
    "affected" => [],
    "references" => []
  }

  @cve_json %{
    "cveMetadata" => %{"cveId" => @cve_id, "state" => "RESERVED"},
    "containers" => %{"cna" => @cna_container}
  }

  @published_cve_json %{
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "state" => "PUBLISHED",
      "datePublished" => "2026-04-27T12:00:00.000Z",
      "dateUpdated" => "2026-04-27T12:00:00.000Z"
    },
    "containers" => %{"cna" => @cna_container}
  }

  @updated_cve_json %{
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "state" => "PUBLISHED",
      "datePublished" => "2026-04-27T12:00:00.000Z",
      "dateUpdated" => "2026-04-27T13:00:00.000Z"
    },
    "containers" => %{"cna" => @updated_cna_container}
  }

  defp reservation_json(cve_id, year \\ @year) do
    %{
      "cve_id" => cve_id,
      "cve_year" => to_string(year),
      "owning_cna" => "EEF",
      "requested_by" => %{"cna" => "EEF", "user" => "test@example.com"},
      "reserved" => "#{year}-01-01T00:00:00.000Z",
      "state" => "RESERVED",
      "time" => %{
        "created" => "#{year}-01-01T00:00:00.000Z",
        "modified" => "#{year}-01-01T00:00:00.000Z"
      }
    }
  end

  defp create_case do
    {:ok, %{id: id}} =
      "cases"
      |> CveManagement.Repo.insert_all(
        [%{status: "open", inserted_at: DateTime.utc_now(), updated_at: DateTime.utc_now()}],
        returning: [:id]
      )
      |> then(fn {1, [row]} -> {:ok, row} end)

    Ecto.UUID.load!(id)
  end

  defp reserved_record(cve_id \\ @cve_id, year \\ @year) do
    Ash.create!(CveRecord, %{reservation_json: reservation_json(cve_id, year)},
      action: :reserve,
      authorize?: false
    )
  end

  defp draft_record do
    case_id = create_case()
    record = reserved_record()
    Ash.update!(record, %{case_id: case_id}, action: :assign, authorize?: false)
  end

  defp publishing_record do
    draft = draft_record()
    Ash.update!(draft, %{cve_json: @cve_json}, action: :request_publish, authorize?: false)
  end

  defp published_record do
    record = publishing_record()
    stub_mitre_publish(@published_cve_json)
    Ash.update!(record, %{}, action: :publish, authorize?: false)
  end

  defp pending_record do
    published = published_record()
    new_json = %{@published_cve_json | "containers" => %{"cna" => @updated_cna_container}}
    Ash.update!(published, %{cve_json: new_json}, action: :update, authorize?: false)
  end

  describe "reserve" do
    test "new record starts in :reserved with no case" do
      record = reserved_record()
      assert record.state == :reserved
      assert record.case_id == nil
      assert record.cve_json == nil
    end

    test "cve_id is derived from reservation_json" do
      record = reserved_record()
      assert Ash.load!(record, [:cve_id], authorize?: false).cve_id == @cve_id
    end

    test "is idempotent via the cve_id identity" do
      reserved_record()
      reserved_record()

      assert Ash.count!(CveRecord, authorize?: false) == 1
    end
  end

  describe "assign" do
    test "transitions reserved → draft and links the case" do
      case_id = create_case()
      record = reserved_record()

      draft = Ash.update!(record, %{case_id: case_id}, action: :assign, authorize?: false)

      assert draft.state == :draft
      assert draft.case_id == case_id
    end

    test "cannot assign a draft record again" do
      draft = draft_record()
      other_case = create_case()

      assert {:error, _} =
               Ash.update(draft, %{case_id: other_case}, action: :assign, authorize?: false)
    end
  end

  describe "publish" do
    test "request_publish transitions draft → publishing with cve_json" do
      record = publishing_record()
      assert record.state == :publishing
      assert record.cve_json == @cve_json
    end

    test "request_publish enqueues a publish job" do
      record = publishing_record()
      assert_triggered(record, :publish)
    end

    test "cannot request_publish a reserved (unassigned) record" do
      record = reserved_record()

      assert {:error, _} =
               Ash.update(record, %{cve_json: @cve_json},
                 action: :request_publish,
                 authorize?: false
               )
    end

    test "publish worker: transitions publishing → published, stores cve_json and published_at" do
      record = publishing_record()
      stub_mitre_publish(@published_cve_json)

      assert {:ok, published} =
               Ash.update(record, %{},
                 action: :publish,
                 authorize?: false,
                 load: [:cve_json, :date_published, :state]
               )

      assert published.state == :published
      assert published.cve_json == @published_cve_json
      assert published.date_published == ~U[2026-04-27 12:00:00Z]
    end

    test "publish trigger runs and transitions record to published" do
      record = publishing_record()
      stub_mitre_publish(@published_cve_json)

      assert %{success: 2, failure: 0} =
               AshOban.Test.schedule_and_run_triggers({CveRecord, :publish})

      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :published
    end

    test "published record is not eligible for publish trigger" do
      record = published_record()
      refute_would_schedule(record, :publish)
    end

    test "idempotency: publish on already-published record is a no-op" do
      record = published_record()

      assert {:ok, still_published} =
               Ash.update(record, %{}, action: :publish, authorize?: false)

      assert still_published.state == :published
    end

    test "MITRE API error: publish returns error so Oban can retry" do
      record = publishing_record()
      stub_mitre_error(400, %{"message" => "Schema validation failed"})

      assert {:error, _} = Ash.update(record, %{}, action: :publish, authorize?: false)

      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :publishing
    end

    test "GET after PUT fails: publish returns error so Oban can retry" do
      record = publishing_record()
      stub_mitre_put_ok_get_fail(@published_cve_json)

      assert {:error, _} = Ash.update(record, %{}, action: :publish, authorize?: false)

      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :publishing
    end
  end

  describe "update" do
    test "transitions published → pending_update with new cve_json" do
      record = published_record()
      new_json = %{@published_cve_json | "containers" => %{"cna" => @updated_cna_container}}

      assert {:ok, pending} =
               Ash.update(record, %{cve_json: new_json}, action: :update, authorize?: false)

      assert pending.state == :pending_update
      assert pending.cve_json == new_json
    end

    test "updating a record enqueues a push_update job" do
      pending = pending_record()
      assert_triggered(pending, :push_update)
    end

    test "cannot update a non-published record" do
      publishing = publishing_record()

      assert {:error, _} =
               Ash.update(publishing, %{cve_json: @updated_cve_json},
                 action: :update,
                 authorize?: false
               )
    end

    test "full flow: publish → update → push_update worker → back to published" do
      record = published_record()
      new_json = %{@published_cve_json | "containers" => %{"cna" => @updated_cna_container}}

      {:ok, pending} =
        Ash.update(record, %{cve_json: new_json}, action: :update, authorize?: false)

      assert pending.state == :pending_update
      assert_triggered(pending, :push_update)

      stub_mitre_publish(@updated_cve_json)

      assert %{success: 2, failure: 0} =
               AshOban.Test.schedule_and_run_triggers({CveRecord, :push_update})

      result = Ash.get!(CveRecord, record.id, authorize?: false)
      assert result.state == :published
      assert result.cve_json == @updated_cve_json
      assert %DateTime{} = result.last_synced_at
    end

    test "pending_update record is not eligible for sync_from_mitre" do
      pending = pending_record()
      refute_would_schedule(pending, :sync_from_mitre)
    end

    test "idempotency: push_update on already-published record is a no-op" do
      record = pending_record()
      stub_mitre_publish(@updated_cve_json)
      {:ok, already_published} = Ash.update(record, %{}, action: :push_update, authorize?: false)
      assert already_published.state == :published

      assert {:ok, still_published} =
               Ash.update(already_published, %{}, action: :push_update, authorize?: false)

      assert still_published.state == :published
    end

    test "MITRE error: push_update returns error so Oban can retry" do
      record = pending_record()
      stub_mitre_error(503, %{"message" => "Service unavailable"})

      assert {:error, _} = Ash.update(record, %{}, action: :push_update, authorize?: false)

      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :pending_update
    end
  end

  describe "reject" do
    test "rejects a reserved record at MITRE and records the reason" do
      record = reserved_record()
      stub_mitre_reject()

      rejected =
        Ash.update!(record, %{rejection_reason: "No longer needed"},
          action: :reject,
          authorize?: false
        )

      assert rejected.state == :rejected
      assert rejected.rejection_reason == "No longer needed"
      assert %DateTime{} = rejected.rejected_at
    end

    test "rejects a draft record" do
      record = draft_record()
      stub_mitre_reject()

      rejected = Ash.update!(record, %{}, action: :reject, authorize?: false)
      assert rejected.state == :rejected
    end

    test "rejects a published record" do
      record = published_record()
      stub_mitre_reject()

      rejected = Ash.update!(record, %{}, action: :reject, authorize?: false)
      assert rejected.state == :rejected
    end

    test "rejected is terminal: cannot assign or publish afterwards" do
      record = reserved_record()
      stub_mitre_reject()
      rejected = Ash.update!(record, %{}, action: :reject, authorize?: false)

      case_id = create_case()

      assert {:error, _} =
               Ash.update(rejected, %{case_id: case_id}, action: :assign, authorize?: false)

      assert {:error, _} =
               Ash.update(rejected, %{cve_json: @cve_json},
                 action: :request_publish,
                 authorize?: false
               )
    end

    test "MITRE error: record stays in its current state" do
      record = reserved_record()
      stub_mitre_error(500, %{"message" => "Internal server error"})

      assert {:error, _} = Ash.update(record, %{}, action: :reject, authorize?: false)

      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :reserved
    end
  end

  describe "sync" do
    test "updates cve_json and last_synced_at when MITRE has a newer record" do
      record = published_record()
      stub_mitre_get(@updated_cve_json)

      assert {:ok, synced} = Ash.update(record, %{}, action: :sync_from_mitre, authorize?: false)

      assert synced.cve_json == @updated_cve_json
      assert %DateTime{} = synced.last_synced_at
    end

    test "does not update cve_json when MITRE record is not newer" do
      record = published_record()
      stub_mitre_get(@published_cve_json)

      assert {:ok, synced} = Ash.update(record, %{}, action: :sync_from_mitre, authorize?: false)

      assert synced.cve_json == @published_cve_json
      assert %DateTime{} = synced.last_synced_at
    end

    test "sync trigger runs for published records" do
      record = published_record()
      stub_mitre_get(@published_cve_json)

      assert %{success: 2, failure: 0} =
               AshOban.Test.schedule_and_run_triggers(
                 {CveRecord, :sync_from_mitre},
                 scheduled_actions?: true
               )

      assert %DateTime{} = Ash.get!(CveRecord, record.id, authorize?: false).last_synced_at
    end

    test "MITRE error: sync returns error so Oban can retry" do
      record = published_record()
      stub_mitre_error(500, %{"message" => "Internal server error"})

      assert {:error, _} = Ash.update(record, %{}, action: :sync_from_mitre, authorize?: false)
    end
  end

  describe "import" do
    test "imports a new CVE record as published" do
      stub_mitre_list_ids([@cve_id])

      CveRecord
      |> Ash.ActionInput.for_action(:import_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      assert [record] = Ash.read!(CveRecord, authorize?: false, load: [:cve_id])

      assert record.state == :published
      assert record.cve_id == @cve_id
    end

    test "is idempotent: re-importing an existing CVE does not duplicate it" do
      stub_mitre_list_ids([@cve_id])

      CveRecord
      |> Ash.ActionInput.for_action(:import_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      CveRecord
      |> Ash.ActionInput.for_action(:import_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      assert [_] =
               CveRecord
               |> Ash.read!(authorize?: false, load: [:cve_id])
               |> Enum.filter(&(&1.cve_id == @cve_id))
    end

    test "fills cve_json on a local reservation that was published externally" do
      record = reserved_record()
      stub_mitre_list_ids([@cve_id])

      CveRecord
      |> Ash.ActionInput.for_action(:import_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      imported = Ash.get!(CveRecord, record.id, authorize?: false)
      assert imported.state == :published
      assert imported.cve_json == @published_cve_json
      assert Ash.count!(CveRecord, authorize?: false) == 1
    end

    test "import trigger runs on schedule" do
      stub_mitre_list_ids([])

      assert %{success: 1, failure: 0} =
               AshOban.Test.schedule_and_run_triggers(
                 {CveRecord, :import_from_mitre},
                 scheduled_actions?: true,
                 triggers?: false
               )
    end

    test "MITRE GET error causes job to fail so Oban can retry" do
      stub_mitre_list_ids_with_get_error([@cve_id])

      assert_raise Ash.Error.Unknown, fn ->
        CveRecord
        |> Ash.ActionInput.for_action(:import_from_mitre, %{}, authorize?: false)
        |> Ash.run_action!()
      end
    end
  end

  describe "top_up_pool" do
    test "reserves IDs when pool is empty" do
      stub_mitre_reserve(["CVE-#{@year}-1001", "CVE-#{@year}-1002"])

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveRecord, authorize?: false) == 2
    end

    test "skip_on_empty: skips entirely when no records exist at all" do
      Req.Test.stub(MitreCveApi, fn conn ->
        flunk(
          "MITRE should not be called on an empty database with skip_on_empty, got: #{conn.method} #{conn.request_path}"
        )
      end)

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year, skip_on_empty: true}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveRecord, authorize?: false) == 0
    end

    test "scheduled run passes skip_on_empty: empty database is left untouched" do
      Req.Test.stub(MitreCveApi, fn conn ->
        flunk(
          "MITRE should not be called by the scheduled top_up on an empty database, got: #{conn.method} #{conn.request_path}"
        )
      end)

      assert %{success: 1, failure: 0} =
               AshOban.Test.schedule_and_run_triggers(
                 {CveRecord, :top_up_pool},
                 scheduled_actions?: true,
                 triggers?: false
               )

      assert Ash.count!(CveRecord, authorize?: false) == 0
    end

    test "skip_on_empty: tops up normally when any record exists" do
      reserved_record("CVE-#{@year}-1101")
      stub_mitre_reserve(["CVE-#{@year}-1102"])

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year, skip_on_empty: true}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveRecord, authorize?: false) == 2
    end

    test "skip_on_empty: a non-pool record (e.g. imported) counts as non-empty" do
      Ash.create!(CveRecord, %{cve_json: @published_cve_json},
        action: :import,
        authorize?: false
      )

      stub_mitre_reserve(["CVE-#{@year}-1201"])

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year, skip_on_empty: true}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveRecord, authorize?: false) == 2
    end

    test "does not reserve more when pool already meets the minimum" do
      min_size = Application.get_env(:cve_management, :cve_pool_min_size, 10)

      for i <- 1..min_size do
        reserved_record("CVE-#{@year}-#{1000 + i}")
      end

      # No stub needed — MITRE should not be called
      Req.Test.stub(MitreCveApi, fn conn ->
        flunk("MITRE API should not be called when pool is full, got: #{conn.method} #{conn.request_path}")
      end)

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveRecord, authorize?: false) == min_size
    end

    test "only counts open (reserved) records for the current year" do
      min_size = Application.get_env(:cve_management, :cve_pool_min_size, 10)

      # Fill the pool but assign every record to a case (state moves to :draft)
      for i <- 1..min_size do
        case_id = create_case()
        record = reserved_record("CVE-#{@year}-#{2000 + i}")
        Ash.update!(record, %{case_id: case_id}, action: :assign, authorize?: false)
      end

      stub_mitre_reserve(["CVE-#{@year}-9001"])

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      # min_size drafts + at least 1 new open reservation
      assert Ash.count!(CveRecord, authorize?: false) > min_size
    end

    test "is idempotent: calling twice does not create duplicates" do
      min_size = Application.get_env(:cve_management, :cve_pool_min_size, 10)
      ids = Enum.map(1..min_size, &"CVE-#{@year}-#{3000 + &1}")
      stub_mitre_reserve(ids)

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      count_after_first = Ash.count!(CveRecord, authorize?: false)

      Req.Test.stub(MitreCveApi, fn conn ->
        flunk("MITRE should not be called on second top_up when pool is full, got: #{conn.method} #{conn.request_path}")
      end)

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveRecord, authorize?: false) == count_after_first
    end

    test "does not count prior-year reservations toward the current year pool" do
      prior_year = @year - 1

      for i <- 1..Application.get_env(:cve_management, :cve_pool_min_size, 10) do
        reserved_record("CVE-#{prior_year}-#{4000 + i}", prior_year)
      end

      stub_mitre_reserve(["CVE-#{@year}-5001"])

      CveRecord
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      # Prior-year entries untouched; new current-year entries added
      current_year_count =
        CveRecord
        |> Ash.Query.for_read(:available, %{year: @year}, authorize?: false)
        |> Ash.count!(authorize?: false)

      assert current_year_count > 0
    end
  end

  describe "sync_reserved_from_mitre" do
    test "inserts IDs reserved outside the app" do
      stub_mitre_reserve_and_list_reserved([], ["CVE-#{@year}-6001", "CVE-#{@year}-6002"])

      CveRecord
      |> Ash.ActionInput.for_action(:sync_reserved_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveRecord, authorize?: false) == 2
    end

    test "does not duplicate existing reservations" do
      reserved_record("CVE-#{@year}-7001")

      stub_mitre_reserve_and_list_reserved([], ["CVE-#{@year}-7001"])

      CveRecord
      |> Ash.ActionInput.for_action(:sync_reserved_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveRecord, authorize?: false) == 1
    end

    test "marks local reservations rejected when MITRE has rejected them externally" do
      reserved_record("CVE-#{@year}-8001")
      reserved_record("CVE-#{@year}-8002")

      Req.Test.stub(MitreCveApi, fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)

        cond do
          conn.method == "GET" && conn.query_params["state"] == "RESERVED" ->
            Req.Test.json(conn, %{"cve_ids" => []})

          conn.method == "GET" && conn.query_params["state"] == "REJECTED" ->
            entries =
              if conn.query_params["page"] == "1",
                do: [%{"cve_id" => "CVE-#{@year}-8001"}],
                else: []

            Req.Test.json(conn, %{"cve_ids" => entries})

          true ->
            Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
        end
      end)

      CveRecord
      |> Ash.ActionInput.for_action(:sync_reserved_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      records = Ash.read!(CveRecord, authorize?: false, load: [:cve_id])
      by_id = Map.new(records, &{&1.cve_id, &1})

      assert by_id["CVE-#{@year}-8001"].state == :rejected
      assert by_id["CVE-#{@year}-8002"].state == :reserved
    end
  end

  describe "reject_stale" do
    test "rejects prior-year open reservations at MITRE and keeps them as tombstones" do
      prior_year = @year - 1
      reserved_record("CVE-#{prior_year}-9001", prior_year)
      reserved_record("CVE-#{@year}-9002")

      stub_mitre_reject()

      CveRecord
      |> Ash.ActionInput.for_action(:run_reject_stale, %{}, authorize?: false)
      |> Ash.run_action!()

      records = Ash.read!(CveRecord, authorize?: false, load: [:cve_id])
      by_id = Map.new(records, &{&1.cve_id, &1})

      assert by_id["CVE-#{prior_year}-9001"].state == :rejected
      assert by_id["CVE-#{@year}-9002"].state == :reserved
    end

    test "does not reject assigned (draft) prior-year reservations" do
      prior_year = @year - 1
      case_id = create_case()
      record = reserved_record("CVE-#{prior_year}-9003", prior_year)
      Ash.update!(record, %{case_id: case_id}, action: :assign, authorize?: false)

      # MITRE should not be called
      Req.Test.stub(MitreCveApi, fn conn ->
        flunk("MITRE should not be called for assigned reservations, got: #{conn.method} #{conn.request_path}")
      end)

      CveRecord
      |> Ash.ActionInput.for_action(:run_reject_stale, %{}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
    end
  end

  defp stub_mitre_publish(response_json) do
    Req.Test.stub(MitreCveApi, fn conn ->
      cond do
        conn.method in ["POST", "PUT"] -> Req.Test.json(conn, response_json)
        conn.method == "GET" -> Req.Test.json(conn, response_json)
        true -> Plug.Conn.send_resp(conn, 404, "not found")
      end
    end)
  end

  defp stub_mitre_get(response_json) do
    Req.Test.stub(MitreCveApi, fn conn ->
      if conn.method == "GET" do
        Req.Test.json(conn, response_json)
      else
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)
  end

  defp stub_mitre_reject do
    Req.Test.stub(MitreCveApi, fn conn ->
      if conn.method == "PUT" do
        Req.Test.json(conn, %{"message" => "CVE ID rejected"})
      else
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)
  end

  defp stub_mitre_put_ok_get_fail(put_response) do
    calls = :counters.new(1, [])

    Req.Test.stub(MitreCveApi, fn conn ->
      if :counters.get(calls, 1) == 0 do
        :counters.add(calls, 1, 1)
        Req.Test.json(conn, put_response)
      else
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(500, Jason.encode!(%{"message" => "Internal error"}))
      end
    end)
  end

  defp stub_mitre_error(status, body) do
    Req.Test.stub(MitreCveApi, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(status, Jason.encode!(body))
    end)
  end

  defp stub_mitre_list_ids(ids) do
    cve_id_entries = Enum.map(ids, &%{"cve_id" => &1})
    Req.Test.stub(MitreCveApi, &handle_list_ids_request(&1, cve_id_entries))
  end

  defp handle_list_ids_request(conn, cve_id_entries) do
    conn = Plug.Conn.fetch_query_params(conn)

    cond do
      conn.method == "GET" && String.ends_with?(conn.request_path, "/cve-id") ->
        entries = if conn.query_params["page"] == "1", do: cve_id_entries, else: []
        Req.Test.json(conn, %{"cve_ids" => entries})

      conn.method == "GET" ->
        Req.Test.json(conn, @published_cve_json)

      true ->
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
    end
  end

  defp stub_mitre_list_ids_with_get_error(ids) do
    cve_id_entries = Enum.map(ids, &%{"cve_id" => &1})
    Req.Test.stub(MitreCveApi, &handle_list_ids_with_get_error_request(&1, cve_id_entries))
  end

  defp handle_list_ids_with_get_error_request(conn, cve_id_entries) do
    conn = Plug.Conn.fetch_query_params(conn)

    cond do
      conn.method == "GET" && String.ends_with?(conn.request_path, "/cve-id") ->
        entries = if conn.query_params["page"] == "1", do: cve_id_entries, else: []
        Req.Test.json(conn, %{"cve_ids" => entries})

      conn.method == "GET" ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(500, Jason.encode!(%{"message" => "Internal server error"}))

      true ->
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
    end
  end

  defp stub_mitre_reserve(ids) do
    Req.Test.stub(MitreCveApi, &handle_reserve_request(&1, ids))
  end

  defp handle_reserve_request(conn, ids) do
    conn = Plug.Conn.fetch_query_params(conn)

    cond do
      conn.method == "POST" && String.ends_with?(conn.request_path, "/cve-id") ->
        Req.Test.json(conn, %{"cve_ids" => Enum.map(ids, &reservation_json/1)})

      conn.method == "GET" && String.ends_with?(conn.request_path, "/cve-id") ->
        Req.Test.json(conn, %{"cve_ids" => []})

      true ->
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
    end
  end

  defp stub_mitre_reserve_and_list_reserved(reserve_ids, reserved_ids) do
    Req.Test.stub(MitreCveApi, &handle_reserve_and_list_request(&1, reserve_ids, reserved_ids))
  end

  defp handle_reserve_and_list_request(conn, reserve_ids, reserved_ids) do
    conn = Plug.Conn.fetch_query_params(conn)

    cond do
      conn.method == "POST" ->
        Req.Test.json(conn, %{"cve_ids" => Enum.map(reserve_ids, &reservation_json/1)})

      conn.method == "GET" && conn.query_params["state"] == "RESERVED" ->
        entries =
          if conn.query_params["page"] == "1",
            do: Enum.map(reserved_ids, &reservation_json/1),
            else: []

        Req.Test.json(conn, %{"cve_ids" => entries})

      conn.method == "GET" && conn.query_params["state"] in ["REJECTED", "PUBLISHED"] ->
        Req.Test.json(conn, %{"cve_ids" => []})

      true ->
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
    end
  end
end
