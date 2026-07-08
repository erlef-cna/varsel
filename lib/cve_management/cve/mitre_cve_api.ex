# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.MitreCveApi do
  @moduledoc """
  Thin client for the MITRE CVE Services API.

  Reads connection config from `Application.get_env(:cve_management, :mitre_cve_api)`:

      config :cve_management, :mitre_cve_api,
        base_url: "https://cveawg-test.mitre.org/api",
        org: "...",
        user: "...",
        api_key: "..."
  """

  @type cve_id :: String.t()

  @doc """
  Streams all CVE IDs owned by the configured org, fetching pages lazily.

  Each element is a CVE ID string. The stream halts on the first API error,
  raising `RuntimeError`.
  """
  @spec stream_ids() :: Enumerable.t()
  def stream_ids do
    "PUBLISHED" |> stream_id_objects() |> Stream.map(& &1["cve_id"])
  end

  @doc """
  Submits (POST) the CNA container JSON for a new CVE ID to MITRE.

  Returns `{:ok, response_body}` on HTTP 200, `{:error, reason}` otherwise.
  `reason` is a human-readable string suitable for storing in `error_message`.
  """
  @spec publish(cve_id(), map()) :: {:ok, map()} | {:error, String.t()}
  def publish(cve_id, cna_container) do
    req = build_req()

    case Req.post(req, url: "/cve/#{cve_id}/cna", json: %{"cnaContainer" => cna_container}) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, format_error(status, body)}

      {:error, exception} ->
        {:error, Exception.message(exception)}
    end
  end

  @doc """
  Updates (PUT) the CNA container JSON for an existing CVE ID at MITRE.

  Returns `{:ok, response_body}` on HTTP 200, `{:error, reason}` otherwise.
  """
  @spec update_cna(cve_id(), map()) :: {:ok, map()} | {:error, String.t()}
  def update_cna(cve_id, cna_container) do
    req = build_req()

    case Req.put(req, url: "/cve/#{cve_id}/cna", json: %{"cnaContainer" => cna_container}) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, format_error(status, body)}

      {:error, exception} ->
        {:error, Exception.message(exception)}
    end
  end

  @doc """
  Reserves `amount` CVE IDs for the given `year` from MITRE.

  Returns `{:ok, [reservation_json]}` where each element is the raw reservation object
  returned by the MITRE API (suitable for storing as `reservation_json` on `CveRecord`).
  Returns `{:error, reason}` on failure.
  """
  @spec reserve(pos_integer(), pos_integer()) :: {:ok, [map()]} | {:error, String.t()}
  def reserve(year, amount) do
    req = build_req()
    cfg = Application.get_env(:cve_management, :mitre_cve_api, [])
    org = Keyword.fetch!(cfg, :org)

    case Req.post(req,
           url: "/cve-id",
           params: [amount: amount, cve_year: year, short_name: org, batch_type: "nonsequential"]
         ) do
      {:ok, %{status: 200, body: %{"cve_ids" => ids}}} ->
        {:ok, ids}

      {:ok, %{status: status, body: body}} ->
        {:error, format_error(status, body)}

      {:error, exception} ->
        {:error, Exception.message(exception)}
    end
  end

  @doc """
  Streams all CVE reservations in the `RESERVED` state owned by the configured org.

  Each element is the raw reservation JSON object from the MITRE API. The stream halts
  on the first API error, raising `RuntimeError`.
  """
  @spec stream_reserved_ids() :: Enumerable.t()
  def stream_reserved_ids do
    stream_id_objects("RESERVED")
  end

  @doc """
  Streams all CVE IDs in the `REJECTED` state owned by the configured org.

  Each element is a CVE ID string. The stream halts on the first API error,
  raising `RuntimeError`.
  """
  @spec stream_rejected_ids() :: Enumerable.t()
  def stream_rejected_ids do
    req = build_req()

    Stream.resource(fn -> {req, 1} end, &fetch_rejected_ids_page/1, fn _ -> :ok end)
  end

  defp fetch_rejected_ids_page(:done), do: {:halt, nil}

  defp fetch_rejected_ids_page({req, page}) do
    case Req.get(req, url: "/cve-id", params: [state: "REJECTED", page: page]) do
      {:ok, %{status: 200, body: %{"cve_ids" => ids}}} ->
        cve_ids = Enum.map(ids, & &1["cve_id"])
        next = if ids == [], do: :done, else: {req, page + 1}
        {cve_ids, next}

      {:ok, %{status: status, body: body}} ->
        raise "MITRE API error listing rejected CVE IDs: #{format_error(status, body)}"

      {:error, exception} ->
        raise "MITRE API error listing rejected CVE IDs: #{Exception.message(exception)}"
    end
  end

  @doc """
  Rejects the given CVE ID at MITRE (marks it as REJECTED).

  Returns `{:ok, response_body}` on HTTP 200, `{:error, reason}` otherwise.
  """
  @spec reject(cve_id()) :: {:ok, map()} | {:error, String.t()}
  def reject(cve_id) do
    req = build_req()

    case Req.put(req, url: "/cve-id/#{cve_id}", json: %{"state" => "REJECT"}) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, format_error(status, body)}

      {:error, exception} ->
        {:error, Exception.message(exception)}
    end
  end

  @doc """
  Fetches the full CVE record from MITRE.

  Returns `{:ok, response_body}` on HTTP 200, `{:error, reason}` otherwise.
  """
  @spec get(cve_id()) :: {:ok, map()} | {:error, String.t()}
  def get(cve_id) do
    req = build_req()

    case Req.get(req, url: "/cve/#{cve_id}") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, format_error(status, body)}

      {:error, exception} ->
        {:error, Exception.message(exception)}
    end
  end

  defp stream_id_objects(state) do
    req = build_req()
    Stream.resource(fn -> {req, 1} end, &fetch_id_objects_page(&1, state), fn _ -> :ok end)
  end

  defp fetch_id_objects_page(:done, _state), do: {:halt, nil}

  defp fetch_id_objects_page({req, page}, state) do
    case Req.get(req, url: "/cve-id", params: [state: state, page: page]) do
      {:ok, %{status: 200, body: %{"cve_ids" => ids}}} ->
        next = if ids == [], do: :done, else: {req, page + 1}
        {ids, next}

      {:ok, %{status: status, body: body}} ->
        raise "MITRE API error listing CVE IDs (state=#{state}): #{format_error(status, body)}"

      {:error, exception} ->
        raise "MITRE API error listing CVE IDs (state=#{state}): #{Exception.message(exception)}"
    end
  end

  @extra_req_opts Keyword.take(
                    Application.compile_env(:cve_management, :mitre_cve_api, []),
                    [:plug]
                  )

  defp build_req do
    cfg = Application.get_env(:cve_management, :mitre_cve_api, [])

    base_opts = [
      base_url: Keyword.fetch!(cfg, :base_url),
      retry: false,
      headers: [
        {"CVE-API-ORG", Keyword.fetch!(cfg, :org)},
        {"CVE-API-USER", Keyword.fetch!(cfg, :user)},
        {"CVE-API-KEY", Keyword.fetch!(cfg, :api_key)}
      ]
    ]

    Req.new(base_opts ++ @extra_req_opts)
  end

  defp format_error(status, body) when is_map(body) do
    message = Map.get(body, "message") || Map.get(body, "error") || inspect(body)
    "MITRE API error #{status}: #{message}"
  end

  defp format_error(status, body), do: "MITRE API error #{status}: #{inspect(body)}"
end
