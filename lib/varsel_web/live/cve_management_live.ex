# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.VarselLive do
  @moduledoc """
  POC-only CVE management: list every CVE record across its whole lifecycle,
  reserve a new draft from the pool, reject a record, and manually trigger a
  MITRE import + sync ahead of the nightly schedule.

  Access is gated by the `:live_poc_required` on_mount hook. Editing a record's
  JSON lives on `VarselWeb.VarselEditLive`.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]

  alias Varsel.CVE
  alias Varsel.CVE.CveRecord

  require Ash.Query

  # States a record may be rejected from (the :reject state-machine `from` set).
  @rejectable [:reserved, :draft, :published]
  # States whose cve_json can be edited (:request_publish / :update `from` sets).
  @editable [:draft, :published, :pending_update]

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(page_title: "CVE Management", mitre_syncing?: false)
      |> keep_live(:cve_records, &list_cve_records/1, subscribe: "cve_record:all", results: :lose)

    {:ok, socket}
  end

  @impl Phoenix.LiveView
  def handle_event("sync_with_mitre", _params, socket) do
    actor = socket.assigns.current_user

    socket =
      socket
      |> assign(mitre_syncing?: true)
      |> start_async(:mitre_sync, fn ->
        CVE.import_cves_from_mitre!(%{}, actor: actor)
        CVE.sync_reserved_cves_from_mitre!(%{}, actor: actor)

        CveRecord
        |> Ash.Query.filter(state == :published)
        |> Ash.bulk_update!(:sync_from_mitre, %{},
          actor: actor,
          notify?: true,
          return_errors?: true,
          strategy: :stream,
          allow_stream_with: :full_read
        )

        :ok
      end)

    {:noreply, socket}
  end

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

  @impl Phoenix.LiveView
  def handle_async(:mitre_sync, {:ok, :ok}, socket) do
    {:noreply,
     socket
     |> assign(mitre_syncing?: false)
     |> put_flash(:info, "MITRE import and sync finished.")}
  end

  def handle_async(:mitre_sync, {:exit, reason}, socket) do
    {:noreply,
     socket
     |> assign(mitre_syncing?: false)
     |> put_flash(:error, "MITRE sync failed: #{Exception.format_exit(reason)}")}
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
          <button class="btn btn-sm" phx-click="sync_with_mitre" disabled={@mitre_syncing?}>
            {if @mitre_syncing?, do: "Syncing…", else: "Sync with MITRE"}
          </button>
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
