# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ReportTriageLive do
  @moduledoc """
  Vulnerability reports, in the two shapes the same route serves.

  For a POC this is the triage queue: list inbound reports, mark them under
  triage, reject them, or accept them into a case — either a fresh draft case
  (titled from the report summary) or an existing open case, completing the
  report → case intake path. Accepting navigates straight to the case
  workspace.

  For any other reporter it is a simplified list of their own reports (summary
  and current status only) — the `:list_reports` read policy does the scoping.
  They cannot triage, but may withdraw a report the CNA has not picked up yet.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]

  alias Varsel.Cases
  alias Varsel.CVE

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    triage? = socket.assigns.current_user.role == :poc

    socket =
      socket
      |> assign(
        page_title: if(triage?, do: "Report Triage", else: "My Reports"),
        triage?: triage?,
        filter: "open"
      )
      |> keep_live(:reports, &list_reports/1,
        subscribe: "vulnerability_report:all",
        results: :lose
      )

    {:ok, if(triage?, do: assign_open_cases(socket), else: socket)}
  end

  @impl Phoenix.LiveView
  def handle_event("filter", %{"filter" => filter}, socket) do
    {:noreply, assign(socket, filter: filter)}
  end

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

  def handle_event("withdraw", %{"report_id" => report_id}, socket) do
    act(socket, report_id, "withdrawn", fn report, actor ->
      CVE.withdraw_vulnerability_report(report, actor: actor)
    end)
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

  # The triage queue defaults to the reports still needing action; resolved
  # reports stay reachable behind their own tabs.
  defp visible_reports(reports, "open"), do: Enum.filter(reports, &actionable?(&1.state))
  defp visible_reports(reports, "accepted"), do: Enum.filter(reports, &(&1.state == :accepted))
  defp visible_reports(reports, "rejected"), do: Enum.filter(reports, &(&1.state == :rejected))
  defp visible_reports(reports, _all), do: reports

  defp tile_options(reports) do
    for {filter, dot} <- [
          {"open", "bg-warning"},
          {"accepted", "bg-success"},
          {"rejected", "bg-error"},
          {"all", nil}
        ] do
      %{
        value: filter,
        label: if(filter == "all", do: "All reports", else: Phoenix.Naming.humanize(filter)),
        count: length(visible_reports(reports, filter)),
        dot: dot
      }
    end
  end

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")

  # Jason, not the stdlib JSON module: only Jason has a pretty printer.
  defp pretty_json(value), do: Jason.encode!(value, pretty: true)

  defp case_label(case_record) do
    [case_record.cve_id, case_record.title || "Untitled"]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" — ")
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <.page_header>
      <:eyebrow>CNA Console</:eyebrow>
      <:title>{if @triage?, do: "Report Triage", else: "My Reports"}</:title>
      <:subtitle :if={@triage?}>
        Inbound vulnerability reports: triage, accept into a case, or reject.
      </:subtitle>
      <:subtitle :if={not @triage?}>
        Reports you submitted. The CNA team triages every report and follows up with you once it
        has been reviewed.
      </:subtitle>
      <:actions>
        <.link navigate={~p"/report"} class="btn btn-sm btn-eef">Submit a report</.link>
      </:actions>
    </.page_header>

    <.page_container>
      <div :if={@triage?} class="mb-4">
        <.stat_tiles active={@filter} options={tile_options(@reports)} />
      </div>

      <div
        :for={report <- visible_reports(@reports, if(@triage?, do: @filter, else: "all"))}
        class="card bg-base-200 mb-4"
      >
        <div class="card-body p-4">
          <div class="flex items-start justify-between gap-4">
            <div>
              <h3 class="font-semibold">{report.summary}</h3>
              <p class="text-xs text-base-content/60">
                <span :if={@triage?}>by {report.reporter.name || report.reporter.email} · </span>
                {format_dt(report.inserted_at)}
              </p>
              <p :if={report.triage_notes} class="text-sm text-base-content/70 mt-1 italic">
                {report.triage_notes}
              </p>
            </div>
            <div class="flex items-center gap-3 shrink-0">
              <span class={["badge badge-sm", state_badge_class(report.state)]}>
                {report.state}
              </span>
              <button
                :if={not @triage? and report.state == :submitted}
                type="button"
                phx-click="withdraw"
                phx-value-report_id={report.id}
                class="btn btn-outline btn-error btn-sm"
                data-confirm="Withdraw this report? The CNA team will stop triaging it."
              >
                Withdraw
              </button>
            </div>
          </div>

          <details :if={@triage?} class="mt-1">
            <summary class="cursor-pointer text-sm text-base-content/60">Report payload</summary>
            <.code_block source={pretty_json(report.report_json)} class="mt-1 max-h-72" />
          </details>

          <.link
            :if={@triage? and report.case_id}
            navigate={~p"/cases/#{report.case_id}"}
            class="link text-sm self-start"
          >
            View the case this report became
          </.link>

          <div :if={@triage? and actionable?(report.state)} class="mt-2 space-y-2">
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

      <.empty_state :if={@reports == []}>
        {if @triage?, do: "No reports here.", else: "You have not submitted any reports yet."}
      </.empty_state>

      <.empty_state :if={@triage? and @reports != [] and visible_reports(@reports, @filter) == []}>
        {if @filter == "open", do: "No reports waiting for triage.", else: "No reports here."}
      </.empty_state>
    </.page_container>
    """
  end
end
