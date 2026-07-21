# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseManagementLive do
  @moduledoc """
  Case list for POCs and assigned supporters.

  POCs see every case and can open new ones; supporters see the cases they
  are assigned to (the read policy scopes the list). The queue-board layout:
  a console header band, one clickable stat tile per state (the overview and
  the filter are the same control), and a paginated, searchable list card.
  Everything else happens on `VarselWeb.CaseDetailLive`.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.LivePagination, only: [change_page: 3]

  alias Varsel.Cases
  alias Varsel.Cases.Case
  alias Varsel.Cases.Case.State

  require Ash.Query

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(page_title: "Cases", filter: "all", query: "", state_counts: %{})
      |> keep_cases_live()

    {:ok, socket}
  end

  # (Re)binds the paginated case page to the current filter/search. On a
  # narrowing change the subscription is torn down first so keep_live can
  # re-subscribe without stacking duplicate PubSub deliveries.
  defp keep_cases_live(socket) do
    socket.endpoint.unsubscribe("case:all")

    keep_live(socket, :cases, &list_cases/2,
      subscribe: "case:all",
      results: :lose,
      after_fetch: &assign_state_counts/2
    )
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

  def handle_event("filter", %{"filter" => filter}, socket) do
    {:noreply, socket |> assign(filter: filter) |> keep_cases_live()}
  end

  def handle_event("search", %{"query" => query}, socket) do
    {:noreply, socket |> assign(query: query) |> keep_cases_live()}
  end

  def handle_event("paginate", %{"page" => target}, socket) do
    {:noreply, change_page(socket, :cases, target)}
  end

  defp list_cases(socket, page_opts) do
    Cases.list_cases!(
      actor: socket.assigns.current_user,
      load: [:cve_id, assignments: [:user]],
      query: cases_query(socket.assigns.filter, socket.assigns.query),
      page: page_opts || [count: true, offset: 0]
    )
  end

  # The tiles always show the whole (policy-scoped) queue, independent of the
  # current filter/search.
  defp assign_state_counts(_page, socket) do
    counts =
      [actor: socket.assigns.current_user, query: Ash.Query.select(Case, [:state])]
      |> Cases.list_cases!()
      |> Enum.frequencies_by(& &1.state)

    assign(socket, :state_counts, counts)
  end

  defp cases_query(filter, query) do
    Case
    |> filter_state(filter)
    |> filter_search(query)
  end

  defp filter_state(base, "all"), do: base

  defp filter_state(base, filter) do
    state = Enum.find(State.values(), &(to_string(&1) == filter)) || :none
    Ash.Query.filter(base, state == ^state)
  end

  defp filter_search(base, query) do
    case query |> String.trim() |> String.downcase() do
      "" ->
        base

      term ->
        Ash.Query.filter(
          base,
          contains(string_downcase(title), ^term) or
            contains(string_downcase(cve_record.cve_id), ^term)
        )
    end
  end

  defp tile_options(counts) do
    all = %{value: "all", label: "All cases", count: counts |> Map.values() |> Enum.sum()}

    state_tiles =
      for state <- State.values() do
        %{
          value: to_string(state),
          label: Phoenix.Naming.humanize(state),
          count: Map.get(counts, state, 0),
          dot: state_dot(state)
        }
      end

    [all | state_tiles]
  end

  defp state_dot(:draft), do: "bg-warning"
  defp state_dot(:review), do: "bg-info"
  defp state_dot(:approved), do: "bg-accent"
  defp state_dot(:publishing), do: "bg-info"
  defp state_dot(:published), do: "bg-success"
  defp state_dot(_closed), do: "bg-base-content/30"

  defp assignee_names(case_record) do
    Enum.map_join(case_record.assignments, ", ", fn assignment ->
      assignment.user.name || assignment.user.github_handle || assignment.user.email
    end)
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

  defp count_label(count, singular) when is_integer(count) do
    if count == 1, do: "1 #{singular}", else: "#{count} #{singular}s"
  end

  defp count_label(_count, singular), do: "#{singular}s"

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <.console_header
      title="Cases"
      subtitle="Structured vulnerability cases from intake to publication."
    >
      <:actions>
        <form :if={poc?(@current_user)} phx-submit="open_case" class="flex items-center gap-2">
          <input
            type="text"
            name="title"
            placeholder="Working title"
            required
            class="input input-bordered input-sm w-56"
          />
          <button type="submit" class="btn btn-sm btn-eef">Open case</button>
        </form>
      </:actions>
    </.console_header>

    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-6">
      <.stat_tiles active={@filter} options={tile_options(@state_counts)} />

      <div class="rounded-box border border-base-300 bg-base-200 overflow-hidden mt-4">
        <div class="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-b border-base-300">
          <span class="text-sm text-base-content/70 tabular-nums">
            {count_label(@cases.count, "case")}
          </span>
          <form id="case-search" phx-change="search" phx-submit="search">
            <.console_search value={@query} placeholder="Search title or CVE ID…" />
          </form>
        </div>

        <div class="overflow-x-auto">
          <table class="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>CVE ID</th>
                <th>State</th>
                <th>Assigned</th>
                <th>Updated</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={case_record <- @cases.results} class="hover:bg-base-300/40">
                <td class="max-w-md truncate">
                  <.link navigate={~p"/cases/#{case_record.id}"} class="link link-hover font-semibold">
                    {case_record.title || "Untitled"}
                  </.link>
                </td>
                <td class="font-mono text-xs whitespace-nowrap text-base-content/70">
                  {case_record.cve_id || "—"}
                </td>
                <td>
                  <.state dot={state_dot(case_record.state)}>
                    {Phoenix.Naming.humanize(case_record.state)}
                  </.state>
                </td>
                <td class="max-w-48 truncate text-sm text-base-content/70">
                  {assignee_names(case_record)}
                </td>
                <td class="whitespace-nowrap tabular-nums text-base-content/70">
                  {format_dt(case_record.updated_at)}
                </td>
                <td class="text-right">
                  <.link
                    navigate={~p"/cases/#{case_record.id}"}
                    class="link link-hover text-primary text-sm font-medium"
                  >
                    Open
                  </.link>
                </td>
              </tr>
            </tbody>
          </table>

          <p :if={@cases.results == []} class="text-center text-base-content/60 py-8">
            No cases match.
          </p>
        </div>

        <div
          :if={is_integer(@cases.count) and @cases.count > @cases.limit}
          class="flex flex-wrap items-center justify-between gap-3 px-4 py-2 border-t border-base-300"
        >
          <span class="text-xs text-base-content/60">{@cases.limit} per page</span>
          <.pagination page={@cases} />
        </div>
      </div>
    </div>
    """
  end
end
