# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ReportTriageLive do
  @moduledoc """
  POC report triage: list inbound vulnerability reports, mark them under
  triage, reject them, or accept them into a case — either a fresh draft case
  (titled from the report summary) or an existing open case, completing the
  report → case intake path. Accepting navigates straight to the case
  workspace.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4, handle_live: 3]

  alias Varsel.Cases
  alias Varsel.CVE

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(page_title: "Report Triage")
      |> keep_live(:reports, &list_reports/1,
        subscribe: "vulnerability_report:all",
        results: :lose
      )
      |> assign_open_cases()

    {:ok, socket}
  end

  @impl Phoenix.LiveView
  def handle_info(%Phoenix.Socket.Broadcast{topic: topic, payload: %Ash.Notifier.Notification{}}, socket) do
    {:noreply, handle_live(socket, topic, :reports)}
  end

  @impl Phoenix.LiveView
  def handle_event("triage", %{"report_id" => report_id, "triage_notes" => notes}, socket) do
    act(socket, report_id, "marked under triage", fn report, actor ->
      CVE.triage_vulnerability_report(report, %{triage_notes: presence(notes)}, actor: actor)
    end)
  end

  def handle_event("reject", %{"report_id" => report_id, "triage_notes" => notes}, socket) do
    act(socket, report_id, "rejected", fn report, actor ->
      CVE.reject_vulnerability_report(report, %{triage_notes: presence(notes)}, actor: actor)
    end)
  end

  def handle_event("accept", %{"report_id" => report_id} = params, socket) do
    report = find_report(socket, report_id)
    args = %{case_id: presence(params["case_id"]), triage_notes: presence(params["triage_notes"])}

    case CVE.accept_vulnerability_report(report, args, actor: socket.assigns.current_user) do
      {:ok, accepted} ->
        {:noreply,
         socket
         |> put_flash(:info, "Report accepted into a case.")
         |> push_navigate(to: ~p"/cases/#{accepted.case_id}")}

      {:error, error} ->
        {:noreply, put_flash(socket, :error, errors_to_string(error))}
    end
  end

  defp act(socket, report_id, verb, fun) do
    socket =
      case fun.(find_report(socket, report_id), socket.assigns.current_user) do
        # The list refreshes via the pub_sub notification handled above.
        {:ok, _report} -> put_flash(socket, :info, "Report #{verb}.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  defp find_report(socket, report_id) do
    Enum.find(socket.assigns.reports, &(&1.id == report_id))
  end

  defp list_reports(socket) do
    CVE.list_vulnerability_reports!(actor: socket.assigns.current_user, load: [:reporter])
  end

  # Open (non-closed) cases a report can be consolidated into.
  defp assign_open_cases(socket) do
    cases =
      [actor: socket.assigns.current_user, load: [:cve_id]]
      |> Cases.list_cases!()
      |> Enum.reject(&(&1.state == :closed))

    assign(socket, :open_cases, cases)
  end

  defp presence(nil), do: nil

  defp presence(value) when is_binary(value), do: if(String.trim(value) == "", do: nil, else: value)

  defp errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  defp state_badge_class(:submitted), do: "badge-warning"
  defp state_badge_class(:triaged), do: "badge-info"
  defp state_badge_class(:accepted), do: "badge-success"
  defp state_badge_class(:rejected), do: "badge-error"
  defp state_badge_class(_other), do: "badge-ghost"

  defp actionable?(state), do: state in [:submitted, :triaged]

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")

  defp pretty_json(value), do: Jason.encode!(value, pretty: true)

  defp case_label(case_record) do
    [case_record.cve_id, case_record.title || "Untitled"]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" — ")
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-5xl py-10">
      <Layouts.flash_group flash={@flash} />

      <.header class="mb-6">
        Report Triage
        <:subtitle>Inbound vulnerability reports: triage, accept into a case, or reject.</:subtitle>
      </.header>

      <div :for={report <- @reports} class="card bg-base-200 mb-4">
        <div class="card-body p-4">
          <div class="flex items-start justify-between gap-4">
            <div>
              <h3 class="font-semibold">{report.summary}</h3>
              <p class="text-xs text-base-content/60">
                by {report.reporter.name || report.reporter.email} · {format_dt(report.inserted_at)}
              </p>
              <p :if={report.triage_notes} class="text-sm text-base-content/70 mt-1 italic">
                {report.triage_notes}
              </p>
            </div>
            <span class={["badge badge-sm shrink-0", state_badge_class(report.state)]}>
              {report.state}
            </span>
          </div>

          <details class="mt-1">
            <summary class="cursor-pointer text-sm text-base-content/60">Report payload</summary>
            <pre class="bg-base-300 rounded p-3 text-xs overflow-x-auto max-h-72 mt-1">{pretty_json(report.report_json)}</pre>
          </details>

          <.link
            :if={report.case_id}
            navigate={~p"/cases/#{report.case_id}"}
            class="link text-sm self-start"
          >
            View the case this report became
          </.link>

          <div :if={actionable?(report.state)} class="mt-2 space-y-2">
            <form
              id={"accept-#{report.id}"}
              phx-submit="accept"
              class="flex flex-wrap items-center gap-2"
            >
              <input type="hidden" name="report_id" value={report.id} />
              <select name="case_id" class="select select-bordered select-sm">
                <option value="">New draft case from this report</option>
                <option :for={case_record <- @open_cases} value={case_record.id}>
                  {case_label(case_record)}
                </option>
              </select>
              <input
                type="text"
                name="triage_notes"
                placeholder="Notes (optional)"
                class="input input-bordered input-sm flex-1 min-w-40"
              />
              <button type="submit" class="btn btn-primary btn-sm">Accept into case</button>
            </form>

            <div class="flex flex-wrap items-center gap-2">
              <form
                :if={report.state == :submitted}
                id={"triage-#{report.id}"}
                phx-submit="triage"
                class="flex items-center gap-2"
              >
                <input type="hidden" name="report_id" value={report.id} />
                <input
                  type="text"
                  name="triage_notes"
                  placeholder="Triage notes"
                  class="input input-bordered input-sm w-56"
                />
                <button type="submit" class="btn btn-outline btn-sm">Mark under triage</button>
              </form>

              <form id={"reject-#{report.id}"} phx-submit="reject" class="flex items-center gap-2">
                <input type="hidden" name="report_id" value={report.id} />
                <input
                  type="text"
                  name="triage_notes"
                  placeholder="Why is this rejected?"
                  class="input input-bordered input-sm w-56"
                />
                <button
                  type="submit"
                  class="btn btn-error btn-outline btn-sm"
                  data-confirm="Reject this report?"
                >
                  Reject
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>

      <p :if={@reports == []} class="text-center text-base-content/60 py-8">
        No reports submitted yet.
      </p>
    </div>
    """
  end
end
