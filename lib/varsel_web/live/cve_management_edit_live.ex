# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.VarselEditLive do
  @moduledoc """
  POC-only JSON editor for a single CVE record's `cve_json`.

  Backed by an `AshPhoenix.Form` over the state-appropriate lifecycle action —
  `:request_publish` for a draft, `:update` for a published/pending record — which
  validates the JSON and enqueues the MITRE push job. The `cve_json` map is edited
  as a pretty-printed JSON string in a textarea and decoded into the action's
  `cve_json` param on submit. Access is gated by `:live_poc_required`.
  """
  use VarselWeb, :live_view

  alias Varsel.CVE

  @editable_actions %{draft: :request_publish, published: :update, pending_update: :update}

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    record = CVE.get_cve_record!(id, load: [:cve_id], actor: socket.assigns.current_user)

    {:ok,
     socket
     |> assign(
       record: record,
       page_title: "Edit #{record.cve_id || "CVE"}",
       json_text: encode_json(record.cve_json)
     )
     |> assign_form()}
  end

  # Keep the raw text so a failed save re-renders the user's edits, not the DB value.
  @impl Phoenix.LiveView
  def handle_event("validate", %{"cve_json" => text}, socket) do
    {:noreply, assign(socket, json_text: text)}
  end

  @impl Phoenix.LiveView
  def handle_event("save", %{"cve_json" => text}, socket) do
    case decode_json(text) do
      {:ok, json} ->
        case AshPhoenix.Form.submit(socket.assigns.form, params: %{"cve_json" => json}) do
          {:ok, _updated} ->
            {:noreply,
             socket
             |> put_flash(:info, "Saved — publish/update job enqueued.")
             |> push_navigate(to: ~p"/cves/manage")}

          {:error, form} ->
            {:noreply, assign(socket, form: form, json_text: text)}
        end

      {:error, :invalid_json} ->
        {:noreply, socket |> put_flash(:error, "Invalid JSON.") |> assign(json_text: text)}
    end
  end

  defp assign_form(socket) do
    record = socket.assigns.record

    case Map.fetch(@editable_actions, record.state) do
      {:ok, action} ->
        form =
          record
          |> AshPhoenix.Form.for_update(action, actor: socket.assigns.current_user)
          |> to_form()

        assign(socket, form: form, editable?: true)

      :error ->
        assign(socket, form: nil, editable?: false)
    end
  end

  defp encode_json(nil), do: "{}"
  defp encode_json(map) when is_map(map), do: Jason.encode!(map, pretty: true)

  defp decode_json(text) do
    case Jason.decode(text) do
      {:ok, json} -> {:ok, json}
      {:error, _} -> {:error, :invalid_json}
    end
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

      <div :if={!@editable?} class="alert alert-warning">
        A record in state <span class="font-mono">{@record.state}</span> cannot be edited.
      </div>

      <.form :if={@editable?} for={@form} id="cve-json-form" phx-submit="save" phx-change="validate">
        <.input
          type="textarea"
          name="cve_json"
          value={@json_text}
          rows="30"
          class="w-full textarea font-mono text-sm"
          errors={Enum.map(@form[:cve_json].errors, &translate_error/1)}
        />

        <div class="flex items-center gap-2 mt-4">
          <button type="submit" class="btn btn-primary">Save</button>
          <.link navigate={~p"/cves/manage"} class="btn btn-ghost">Cancel</.link>
        </div>
      </.form>
    </div>
    """
  end
end
