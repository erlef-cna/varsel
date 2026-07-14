# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.VarselLive do
  @moduledoc """
  POC-only CVE management: list every CVE record across its whole lifecycle,
  reserve a new draft from the pool, and reject a record.

  Access is gated by the `:live_poc_required` on_mount hook. Editing a record's
  JSON lives on `VarselWeb.VarselEditLive`.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4, handle_live: 3]

  alias Varsel.CVE

  # States a record may be rejected from (the :reject state-machine `from` set).
  @rejectable [:reserved, :draft, :published]
  # States whose cve_json can be edited (:request_publish / :update `from` sets).
  @editable [:draft, :published, :pending_update]

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(page_title: "CVE Management")
      |> keep_live(:cve_records, &list_cve_records/1, subscribe: "cve_record:all", results: :lose)

    {:ok, socket}
  end

  # Any change to any record broadcasts on "cve_record:all" (see the pub_sub
  # block on Varsel.CVE.CveRecord), which re-runs the list query so every
  # connected POC sees the update without a reload.
  @impl Phoenix.LiveView
  def handle_info(%Phoenix.Socket.Broadcast{topic: topic, payload: %Ash.Notifier.Notification{}}, socket) do
    {:noreply, handle_live(socket, topic, :cve_records)}
  end

  @impl Phoenix.LiveView
  def handle_event("reserve", _params, socket) do
    actor = socket.assigns.current_user

    socket =
      case Enum.find(socket.assigns.cve_records, &(&1.state == :reserved)) do
        nil ->
          put_flash(socket, :error, "No reserved IDs in the pool.")

        record ->
          case CVE.assign_cve_record(record, %{}, actor: actor) do
            {:ok, drafted} ->
              # The list refreshes via the pub_sub notification handled above.
              put_flash(socket, :info, "Reserved #{drafted.cve_id} — now a draft.")

            {:error, error} ->
              put_flash(socket, :error, "Could not reserve: #{errors_to_string(error)}")
          end
      end

    {:noreply, socket}
  end

  def handle_event("reject", %{"record_id" => record_id, "rejection_reason" => reason}, socket) do
    actor = socket.assigns.current_user
    record = Enum.find(socket.assigns.cve_records, &(&1.id == record_id))

    socket =
      case CVE.reject_cve_record(record, %{rejection_reason: reason}, actor: actor) do
        {:ok, rejected} ->
          put_flash(socket, :info, "Rejected #{rejected.cve_id}.")

        {:error, error} ->
          put_flash(socket, :error, "Could not reject: #{errors_to_string(error)}")
      end

    {:noreply, socket}
  end

  defp list_cve_records(socket) do
    CVE.list_all_cve_records!(actor: socket.assigns.current_user)
  end

  defp errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  defp state_badge_class(:reserved), do: "badge-ghost"
  defp state_badge_class(:draft), do: "badge-warning"
  defp state_badge_class(:publishing), do: "badge-info"
  defp state_badge_class(:published), do: "badge-success"
  defp state_badge_class(:pending_update), do: "badge-info"
  defp state_badge_class(:rejected), do: "badge-error"
  defp state_badge_class(_other), do: "badge-ghost"

  defp editable?(state), do: state in @editable
  defp rejectable?(state), do: state in @rejectable

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-10">
      <Layouts.flash_group flash={@flash} />

      <.header class="mb-6">
        CVE Management
        <:subtitle>Reserve, draft, publish, and reject CVE records.</:subtitle>
        <:actions>
          <button class="btn btn-primary btn-sm" phx-click="reserve">
            Reserve a new one
          </button>
        </:actions>
      </.header>

      <div class="overflow-x-auto">
        <table class="table table-zebra">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>State</th>
              <th>Title</th>
              <th>Published</th>
              <th>Updated</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr :for={record <- @cve_records}>
              <td class="font-mono whitespace-nowrap">{record.cve_id || "—"}</td>
              <td>
                <span class={["badge badge-sm", state_badge_class(record.state)]}>
                  {record.state}
                </span>
              </td>
              <td>{record.title || "—"}</td>
              <td class="whitespace-nowrap">{format_dt(record.date_published)}</td>
              <td class="whitespace-nowrap">{format_dt(record.date_updated)}</td>
              <td>
                <div class="flex items-center gap-2 justify-end">
                  <.link
                    :if={editable?(record.state)}
                    navigate={~p"/cves/manage/#{record.id}"}
                    class="btn btn-ghost btn-xs"
                  >
                    Edit
                  </.link>
                  <form
                    :if={rejectable?(record.state)}
                    id={"reject-#{record.id}"}
                    phx-submit="reject"
                    class="flex items-center gap-1"
                  >
                    <input type="hidden" name="record_id" value={record.id} />
                    <input
                      type="text"
                      name="rejection_reason"
                      placeholder="Reason"
                      required
                      class="input input-bordered input-xs w-28"
                    />
                    <button type="submit" class="btn btn-error btn-xs">Reject</button>
                  </form>
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <p :if={@cve_records == []} class="text-center text-base-content/60 py-8">
          No CVE records yet.
        </p>
      </div>
    </div>
    """
  end
end
