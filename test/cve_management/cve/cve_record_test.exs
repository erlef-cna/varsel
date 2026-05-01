# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.CveRecordTest do
  use CveManagement.DataCase, async: false

  alias CveManagement.CVE.CveRecord
  alias CveManagement.CVE.MitreCveApi

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

  defp published_record do
    {:ok, record} = Ash.create(CveRecord, %{cve_json: @cve_json}, authorize?: false)
    stub_mitre_publish(@published_cve_json)
    {:ok, published} = Ash.update(record, %{}, action: :publish, authorize?: false)
    published
  end

  defp pending_record do
    published = published_record()
    new_json = %{@published_cve_json | "containers" => %{"cna" => @updated_cna_container}}

    {:ok, pending} =
      Ash.update(published, %{cve_json: new_json}, action: :update, authorize?: false)

    pending
  end

  describe "create" do
    test "new record starts in :publishing" do
      {:ok, record} = Ash.create(CveRecord, %{cve_json: @cve_json}, authorize?: false)
      assert record.state == :publishing
    end

    test "creating a record enqueues a publish job" do
      {:ok, record} = Ash.create(CveRecord, %{cve_json: @cve_json}, authorize?: false)
      assert_triggered(record, :publish)
    end

    test "publish worker: transitions publishing → published, stores cve_json and published_at" do
      {:ok, record} = Ash.create(CveRecord, %{cve_json: @cve_json}, authorize?: false)
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
      {:ok, record} = Ash.create(CveRecord, %{cve_json: @cve_json}, authorize?: false)
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
      {:ok, record} = Ash.create(CveRecord, %{cve_json: @cve_json}, authorize?: false)
      stub_mitre_error(400, %{"message" => "Schema validation failed"})

      assert {:error, _} = Ash.update(record, %{}, action: :publish, authorize?: false)

      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :publishing
    end

    test "GET after PUT fails: publish returns error so Oban can retry" do
      {:ok, record} = Ash.create(CveRecord, %{cve_json: @cve_json}, authorize?: false)
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
      {:ok, publishing} = Ash.create(CveRecord, %{cve_json: @cve_json}, authorize?: false)

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
end
