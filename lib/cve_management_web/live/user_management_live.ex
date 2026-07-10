# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.UserManagementLive do
  @moduledoc """
  POC-only user management: list all users and change their role.

  Access is gated by the `:live_poc_required` on_mount hook; role changes go
  through the POC-authorized `set_role` action with the current user as actor.
  """
  use CveManagementWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4, handle_live: 3]

  alias CveManagement.Accounts

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
      |> keep_live(:users, &list_users/1, subscribe: "user:all", results: :lose)

    {:ok, socket}
  end

  # Any change to any user (registration, role change) broadcasts on "user:all"
  # (see the pub_sub block on CveManagement.Accounts.User), which re-runs the
  # list query so every connected POC sees the update without a reload.
  @impl Phoenix.LiveView
  def handle_info(%Phoenix.Socket.Broadcast{topic: topic, payload: %Ash.Notifier.Notification{}}, socket) do
    {:noreply, handle_live(socket, topic, :users)}
  end

  @impl Phoenix.LiveView
  def handle_event("set_role", %{"user_id" => user_id, "role" => role}, socket) do
    actor = socket.assigns.current_user
    user = Enum.find(socket.assigns.users, &(&1.id == user_id))

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

  defp list_users(socket) do
    [actor: socket.assigns.current_user]
    |> Accounts.list_users!()
    |> Enum.sort_by(&{&1.role != :poc, display_name(&1)})
  end

  defp role_value(nil), do: ""
  defp role_value(role), do: to_string(role)

  defp display_name(user), do: user.name || user.github_handle || user.email || "user"

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-5xl py-10">
      <Layouts.flash_group flash={@flash} />

      <.header class="mb-6">
        User Management
        <:subtitle>Manage who can access the CNA tooling and their role.</:subtitle>
      </.header>

      <div class="overflow-x-auto">
        <table class="table table-zebra">
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>GitHub</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={user <- @users}>
              <td class="font-medium">
                {user.name || "—"}
                <span :if={user.id == @current_user.id} class="badge badge-ghost badge-sm ml-1">
                  you
                </span>
              </td>
              <td>{user.email || "—"}</td>
              <td>
                <a
                  :if={user.github_handle}
                  href={"https://github.com/#{user.github_handle}"}
                  class="link link-primary"
                  target="_blank"
                  rel="noopener"
                >
                  @{user.github_handle}
                </a>
                <span :if={is_nil(user.github_handle)}>—</span>
              </td>
              <td>
                <form id={"role-#{user.id}"} phx-change="set_role">
                  <input type="hidden" name="user_id" value={user.id} />
                  <select name="role" class="select select-bordered select-sm">
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
    </div>
    """
  end
end
