# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseManagementLive do
  @moduledoc """
  Case list for POCs and assigned supporters.

  POCs see every case and can open new ones; supporters see the cases they
  are assigned to (the read policy scopes the list). Everything else happens
  on `VarselWeb.CaseDetailLive`.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]

  alias Varsel.Cases

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(page_title: "Cases")
      |> keep_live(:cases, &list_cases/1, subscribe: "case:all", results: :lose)

    {:ok, socket}
  end

  @impl Phoenix.LiveView
  def handle_event("open_case", %{"title" => title}, socket) do
    socket =
      case Cases.open_case(%{title: title}, actor: socket.assigns.current_user) do
        {:ok, case_record} ->
          push_navigate(socket, to: ~p"/cases/#{case_record.id}")

        {:error, error} ->
          put_flash(socket, :error, "Could not open case: #{errors_to_string(error)}")
      end

    {:noreply, socket}
  end

  defp list_cases(socket) do
    Cases.list_cases!(actor: socket.assigns.current_user, load: [:cve_id])
  end

  defp errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  defp poc?(%{role: :poc}), do: true
  defp poc?(_user), do: false

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-10">
      <Layouts.flash_group flash={@flash} />

      <.header class="mb-6">
        Cases
        <:subtitle>Structured vulnerability cases from intake to publication.</:subtitle>
        <:actions>
          <form :if={poc?(@current_user)} phx-submit="open_case" class="flex items-center gap-2">
            <input
              type="text"
              name="title"
              placeholder="Working title"
              required
              class="input input-bordered input-sm w-56"
            />
            <button type="submit" class="btn btn-primary btn-sm">Open case</button>
          </form>
        </:actions>
      </.header>

      <div class="overflow-x-auto">
        <table class="table table-zebra">
          <thead>
            <tr>
              <th>Title</th>
              <th>CVE ID</th>
              <th>State</th>
              <th>Updated</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr :for={case_record <- @cases}>
              <td class="max-w-md truncate">{case_record.title || "Untitled"}</td>
              <td class="font-mono whitespace-nowrap">{case_record.cve_id || "—"}</td>
              <td>
                <span class={[
                  "badge badge-sm",
                  VarselWeb.CaseDetailLive.state_badge_class(case_record.state)
                ]}>
                  {case_record.state}
                </span>
              </td>
              <td class="whitespace-nowrap">{format_dt(case_record.updated_at)}</td>
              <td class="text-right">
                <.link navigate={~p"/cases/#{case_record.id}"} class="btn btn-ghost btn-xs">
                  Open
                </.link>
              </td>
            </tr>
          </tbody>
        </table>

        <p :if={@cases == []} class="text-center text-base-content/60 py-8">
          No cases yet.
        </p>
      </div>
    </div>
    """
  end
end
