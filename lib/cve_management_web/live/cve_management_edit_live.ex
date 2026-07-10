# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.CveManagementEditLive do
  @moduledoc """
  POC-only JSON editor for a single CVE record's `cve_json`.

  Saving runs the state-appropriate lifecycle action — `:request_publish` for a
  draft, `:update` for a published/pending record — which validates the JSON and
  enqueues the MITRE push job. Access is gated by `:live_poc_required`.
  """
  use CveManagementWeb, :live_view

  alias CveManagement.CVE

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    record = CVE.get_cve_record!(id, load: [:cve_id], actor: socket.assigns.current_user)

    socket =
      assign(socket,
        record: record,
        page_title: "Edit #{record.cve_id || "CVE"}",
        json_text: encode_json(record.cve_json)
      )

    {:ok, socket}
  end

  # Keep the raw text so a failed save re-renders the user's edits, not the DB value.
  @impl Phoenix.LiveView
  def handle_event("validate", %{"cve_json" => text}, socket) do
    {:noreply, assign(socket, json_text: text)}
  end

  @impl Phoenix.LiveView
  def handle_event("save", %{"cve_json" => text}, socket) do
    record = socket.assigns.record
    actor = socket.assigns.current_user

    with {:ok, json} <- decode_json(text),
         {:ok, _updated} <- save(record, json, actor) do
      {:noreply,
       socket
       |> put_flash(:info, "Saved — publish/update job enqueued.")
       |> push_navigate(to: ~p"/cves/manage")}
    else
      {:error, :invalid_json} ->
        {:noreply, socket |> put_flash(:error, "Invalid JSON.") |> assign(json_text: text)}

      {:error, :not_editable} ->
        {:noreply, put_flash(socket, :error, "Cannot edit a record in state #{record.state}.")}

      {:error, error} ->
        {:noreply,
         socket
         |> put_flash(:error, "Could not save:\n#{errors_to_string(error)}")
         |> assign(json_text: text)}
    end
  end

  # Picks the lifecycle action that matches the record's current state.
  defp save(%{state: :draft} = record, json, actor) do
    CVE.request_publish_cve_record(record, %{cve_json: json}, actor: actor)
  end

  defp save(%{state: state} = record, json, actor) when state in [:published, :pending_update] do
    CVE.update_cve_record(record, %{cve_json: json}, actor: actor)
  end

  defp save(_record, _json, _actor), do: {:error, :not_editable}

  defp encode_json(nil), do: "{}"
  defp encode_json(map) when is_map(map), do: Jason.encode!(map, pretty: true)

  defp decode_json(text) do
    case Jason.decode(text) do
      {:ok, json} -> {:ok, json}
      {:error, _} -> {:error, :invalid_json}
    end
  end

  defp errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-4xl py-10">
      <Layouts.flash_group flash={@flash} />

      <.header class="mb-6">
        Edit {@record.cve_id || "CVE"}
        <:subtitle>
          State: <span class="font-mono">{@record.state}</span>. Saving runs validation and
          enqueues the MITRE push.
        </:subtitle>
      </.header>

      <form id="cve-json-form" phx-submit="save" phx-change="validate">
        <.input
          type="textarea"
          name="cve_json"
          value={@json_text}
          rows="30"
          class="w-full textarea font-mono text-sm"
        />

        <div class="flex items-center gap-2 mt-4">
          <button type="submit" class="btn btn-primary">Save</button>
          <.link navigate={~p"/cves/manage"} class="btn btn-ghost">Cancel</.link>
        </div>
      </form>
    </div>
    """
  end
end
