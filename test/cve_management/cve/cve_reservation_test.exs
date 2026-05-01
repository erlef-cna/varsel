# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.CveReservationTest do
  use CveManagement.DataCase, async: false

  alias CveManagement.CVE.CveReservation
  alias CveManagement.CVE.MitreCveApi

  @year Date.utc_today().year

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

  defp stub_mitre_reject do
    Req.Test.stub(MitreCveApi, fn conn ->
      if conn.method == "PUT" do
        Req.Test.json(conn, %{"message" => "CVE ID rejected"})
      else
        Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
      end
    end)
  end

  defp create_reservation(cve_id, year \\ @year) do
    Ash.create!(CveReservation, %{reservation_json: reservation_json(cve_id, year)},
      action: :reserve,
      authorize?: false
    )
  end

  defp create_case do
    {:ok, %{id: id}} =
      "cases"
      |> CveManagement.Repo.insert_all(
        [%{status: "open", inserted_at: DateTime.utc_now(), updated_at: DateTime.utc_now()}],
        returning: [:id]
      )
      |> then(fn {1, [row]} -> {:ok, row} end)

    id
  end

  describe "top_up_pool" do
    test "reserves IDs when pool is empty" do
      stub_mitre_reserve(["CVE-#{@year}-1001", "CVE-#{@year}-1002"])

      CveReservation
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveReservation, authorize?: false) == 2
    end

    test "does not reserve more when pool already meets the minimum" do
      min_size = Application.get_env(:cve_management, :cve_pool_min_size, 10)

      for i <- 1..min_size do
        create_reservation("CVE-#{@year}-#{1000 + i}")
      end

      # No stub needed — MITRE should not be called
      Req.Test.stub(MitreCveApi, fn conn ->
        flunk("MITRE API should not be called when pool is full, got: #{conn.method} #{conn.request_path}")
      end)

      CveReservation
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveReservation, authorize?: false) == min_size
    end

    test "only counts open (unassigned) reservations for the current year" do
      min_size = Application.get_env(:cve_management, :cve_pool_min_size, 10)
      case_id = create_case()

      # Fill the pool but mark all as assigned (case_id set)
      for i <- 1..min_size do
        res = create_reservation("CVE-#{@year}-#{2000 + i}")
        Ash.update!(res, %{case_id: case_id}, action: :assign, authorize?: false)
      end

      stub_mitre_reserve(["CVE-#{@year}-9001"])

      CveReservation
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      # min_size assigned + at least 1 new open reservation
      assert Ash.count!(CveReservation, authorize?: false) > min_size
    end

    test "is idempotent: calling twice does not create duplicates" do
      min_size = Application.get_env(:cve_management, :cve_pool_min_size, 10)
      ids = Enum.map(1..min_size, &"CVE-#{@year}-#{3000 + &1}")
      stub_mitre_reserve(ids)

      CveReservation
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      count_after_first = Ash.count!(CveReservation, authorize?: false)

      Req.Test.stub(MitreCveApi, fn conn ->
        flunk("MITRE should not be called on second top_up when pool is full, got: #{conn.method} #{conn.request_path}")
      end)

      CveReservation
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveReservation, authorize?: false) == count_after_first
    end

    test "does not count prior-year reservations toward the current year pool" do
      prior_year = @year - 1

      for i <- 1..Application.get_env(:cve_management, :cve_pool_min_size, 10) do
        create_reservation("CVE-#{prior_year}-#{4000 + i}", prior_year)
      end

      stub_mitre_reserve(["CVE-#{@year}-5001"])

      CveReservation
      |> Ash.ActionInput.for_action(:top_up_pool, %{year: @year}, authorize?: false)
      |> Ash.run_action!()

      # Prior-year entries untouched; new current-year entries added
      current_year_count =
        CveReservation
        |> Ash.Query.for_read(:available, %{year: @year}, authorize?: false)
        |> Ash.count!(authorize?: false)

      assert current_year_count > 0
    end
  end

  describe "sync_reserved_from_mitre" do
    test "inserts IDs reserved outside the app" do
      stub_mitre_reserve_and_list_reserved([], ["CVE-#{@year}-6001", "CVE-#{@year}-6002"])

      CveReservation
      |> Ash.ActionInput.for_action(:sync_reserved_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveReservation, authorize?: false) == 2
    end

    test "does not duplicate existing reservations" do
      create_reservation("CVE-#{@year}-7001")

      stub_mitre_reserve_and_list_reserved([], ["CVE-#{@year}-7001"])

      CveReservation
      |> Ash.ActionInput.for_action(:sync_reserved_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveReservation, authorize?: false) == 1
    end

    test "destroys local reservations that MITRE has rejected" do
      create_reservation("CVE-#{@year}-8001")
      create_reservation("CVE-#{@year}-8002")

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

          conn.method == "GET" && conn.query_params["state"] == "PUBLISHED" ->
            Req.Test.json(conn, %{"cve_ids" => []})

          true ->
            Plug.Conn.send_resp(conn, 405, "Method Not Allowed")
        end
      end)

      CveReservation
      |> Ash.ActionInput.for_action(:sync_reserved_from_mitre, %{}, authorize?: false)
      |> Ash.run_action!()

      remaining = Ash.read!(CveReservation, authorize?: false, load: [:cve_id])
      assert length(remaining) == 1
      assert hd(remaining).cve_id == "CVE-#{@year}-8002"
    end
  end

  describe "reject_stale" do
    test "rejects and removes prior-year unassigned reservations" do
      prior_year = @year - 1
      create_reservation("CVE-#{prior_year}-9001", prior_year)
      create_reservation("CVE-#{@year}-9002")

      stub_mitre_reject()

      CveReservation
      |> Ash.ActionInput.for_action(:run_reject_stale, %{}, authorize?: false)
      |> Ash.run_action!()

      remaining = Ash.read!(CveReservation, authorize?: false, load: [:cve_id])
      assert length(remaining) == 1
      assert hd(remaining).cve_id == "CVE-#{@year}-9002"
    end

    test "does not reject assigned prior-year reservations" do
      prior_year = @year - 1
      case_id = create_case()
      res = create_reservation("CVE-#{prior_year}-9003", prior_year)
      Ash.update!(res, %{case_id: case_id}, action: :assign, authorize?: false)

      # MITRE should not be called
      Req.Test.stub(MitreCveApi, fn conn ->
        flunk("MITRE should not be called for assigned reservations, got: #{conn.method} #{conn.request_path}")
      end)

      CveReservation
      |> Ash.ActionInput.for_action(:run_reject_stale, %{}, authorize?: false)
      |> Ash.run_action!()

      assert Ash.count!(CveReservation, authorize?: false) == 1
    end
  end
end
