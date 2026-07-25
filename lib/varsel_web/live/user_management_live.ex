# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.UserManagementLive do
  @moduledoc """
  POC-only user management: list all users and change their role.

  Access is gated by the `:live_poc_required` on_mount hook; role changes go
  through the POC-authorized `set_role` action with the current user as actor.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]

  alias Varsel.Accounts
  alias Varsel.Accounts.User

  @roles [
    {"POC", :poc},
    {"Supporter", :supporter},
    {"None", nil}
  ]

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(page_title: "User Management", roles: @roles)
      |> keep_live(:users, &list_users/2, subscribe: "user:all", results: :lose)

    {:ok, socket}
  end

  @impl Phoenix.LiveView
  def handle_event("paginate", %{"page" => target}, socket) do
    {:noreply, change_page(socket, :users, target)}
  end

  def handle_event("jump_page", %{"page" => target}, socket) do
    {:noreply, jump_to_page(socket, :users, target)}
  end

  def handle_event("set_role", %{"user_id" => user_id, "role" => role}, socket) do
    actor = socket.assigns.current_user
    user = Enum.find(socket.assigns.users.results, &(&1.id == user_id))

    socket =
      case Accounts.set_user_role(user, role, actor: actor) do
        {:ok, _updated} ->
          # The list refreshes via the pub_sub notification handled above.
          put_flash(socket, :info, "Updated #{display_name(user)}.")

        {:error, _error} ->
          put_flash(socket, :error, "Could not update #{display_name(user)}.")
      end

    {:noreply, socket}
  end

  # The keep_live callback: page_opts is nil on the first run and the stored
  # page's options on a refetch, so a role change keeps the page the user is
  # on. Points of contact lead the list, then everyone by display name —
  # sorted in the query, so a page is ordered against the whole table rather
  # than only the rows it happens to hold.
  defp list_users(socket, page_opts) do
    Accounts.list_users!(
      actor: socket.assigns.current_user,
      query: Ash.Query.sort(User, poc_first: :asc, display_name: :asc),
      page: page_opts || [count: true, offset: 0]
    )
  end

  defp role_value(nil), do: ""
  defp role_value(role), do: to_string(role)

  defp display_name(user), do: user.name || user.github_handle || user.email || "user"

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <.page_header>
      <:eyebrow>CNA Console</:eyebrow>
      <:title>Users</:title>
      <:subtitle>Manage who can access the CNA tooling and their role.</:subtitle>
    </.page_header>

    <.page_container>
      <.list_card empty?={@users.results == []}>
        <:empty>No users yet.</:empty>
        <:footer :if={paged?(@users)}>
          <.pagination page={@users} noun="user" />
        </:footer>

        <div class="overflow-x-auto">
          <table class="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>GitHub</th>
                <th class="text-right">Role</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={user <- @users.results} class="hover:bg-base-300/40">
                <td class="font-medium">
                  {user.name || "—"}
                  <span :if={user.id == @current_user.id} class="badge badge-ghost badge-sm ml-1">
                    you
                  </span>
                </td>
                <td class="text-base-content/70">{user.email || "—"}</td>
                <td>
                  <a
                    :if={user.github_handle}
                    href={"https://github.com/#{user.github_handle}"}
                    class="link link-hover text-primary"
                    target="_blank"
                    rel="noopener"
                  >
                    @{user.github_handle}
                  </a>
                  <span :if={is_nil(user.github_handle)} class="text-base-content/50">—</span>
                </td>
                <td class="text-right">
                  <form id={"role-#{user.id}"} phx-change="set_role" class="inline-block">
                    <input type="hidden" name="user_id" value={user.id} />
                    <select name="role" class="select select-bordered select-sm w-32">
                      <option
                        :for={{label, value} <- @roles}
                        value={role_value(value)}
                        selected={user.role == value}
                      >
                        {label}
                      </option>
                    </select>
                  </form>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </.list_card>
    </.page_container>
    """
  end
end
