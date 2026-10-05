# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseReportsLive do
  @moduledoc """
  The Reports tab of a case: the vulnerability reports that led to it, in
  the triage queue's row shape. Reports are acted on in triage and read here.
  """
  use VarselWeb, :live_view

  import VarselWeb.CaseComponents, only: [case_header: 1, report_row: 1]

  alias Varsel.CVE.VulnerabilityReport
  alias VarselWeb.CaseLifecycle

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    socket =
      socket
      |> assign(expanded_payloads: MapSet.new())
      |> CaseLifecycle.mount(id,
        load: [
          :cve_id,
          :cve_record,
          vulnerability_reports: [reporter: [:avatar_url, :display_name]]
        ],
        after_fetch: &after_fetch/2
      )

    {:ok, socket}
  end

  defp after_fetch(case_record, socket) do
    assign(socket, page_title: case_record.title || "Case")
  end

  @impl Phoenix.LiveView
  def handle_event("toggle_payload", %{"report_id" => report_id}, socket) do
    expanded = socket.assigns.expanded_payloads

    expanded =
      if MapSet.member?(expanded, report_id) do
        MapSet.delete(expanded, report_id)
      else
        MapSet.put(expanded, report_id)
      end

    {:noreply, assign(socket, :expanded_payloads, expanded)}
  end

  defp reports(case_record) do
    Enum.sort_by(case_record.vulnerability_reports, & &1.inserted_at, DateTime)
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.app
      flash={@flash}
      current_user={@current_user}
      current_path={@current_path}
      socket={@socket}
    >
      <.case_header
        case_record={@case_record}
        public_href={CaseLifecycle.public_cve_href(@case_record)}
        tabs={CaseLifecycle.tabs(@case_record)}
        active={:reports}
      >
        <:actions>
          <CaseLifecycle.lifecycle_buttons case_record={@case_record} current_user={@current_user} />
        </:actions>
      </.case_header>

      <.page_container>
        <.list_card empty?={@case_record.vulnerability_reports == []}>
          <:note>
            <.count_label count={length(@case_record.vulnerability_reports)} singular="report" />
            <.link
              :if={Ash.can?({VulnerabilityReport, :triage}, @current_user)}
              navigate={~p"/reports"}
              class="link link-hover text-primary ml-2"
            >
              Report triage
            </.link>
          </:note>
          <:empty>No reports led to this case.</:empty>

          <.report_row
            :for={report <- reports(@case_record)}
            id={"case-report-#{report.id}"}
            report={report}
            payload_open?={MapSet.member?(@expanded_payloads, report.id)}
            toggle="toggle_payload"
          />
        </.list_card>
      </.page_container>

      <CaseLifecycle.cve_picker_modal
        :if={@cve_picker}
        case_record={@case_record}
        current_user={@current_user}
        records={@cve_picker}
      />
    </Layouts.app>
    """
  end
end
