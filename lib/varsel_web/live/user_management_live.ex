# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.UserManagementLive do
  @moduledoc """
  POC-only user management: list all users and change their role.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]
  import VarselWeb.UserComponents, only: [avatar_disc: 1]

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
          put_flash(socket, :info, "Updated #{user.display_name}.")

        {:error, _error} ->
          put_flash(socket, :error, "Could not update #{user.display_name}.")
      end

    {:noreply, socket}
  end

  def handle_event("delete_user", %{"user_id" => user_id}, socket) do
    actor = socket.assigns.current_user
    user = Enum.find(socket.assigns.users.results, &(&1.id == user_id))

    case Accounts.delete_user(user, actor: actor) do
      :ok when user_id == actor.id ->
        # Deleting yourself revokes your own tokens, so this page is no longer
        # yours to be on — the session cookie stops authenticating anything.
        {:noreply,
         socket
         |> put_flash(:info, "Your account has been deleted.")
         |> push_navigate(to: ~p"/")}

      :ok ->
        # The list refreshes via the pub_sub notification handled above.
        {:noreply, put_flash(socket, :info, "Deleted #{user.display_name}.")}

      {:error, _error} ->
        {:noreply, put_flash(socket, :error, "Could not delete #{user.display_name}.")}
    end
  end

  # Deleting your own account from here signs you out, so say so; a POC
  # deleting someone else needs to know what survives and what does not.
  defp delete_confirmation(user) do
    """
    Delete #{user.display_name}? Their sign-in providers, API tokens and case \
    assignments go with the account. What they wrote — comments, suggestions \
    and reports — stays, credited to a deleted user. This cannot be undone.\
    """
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
      page: page_opts || [count: true, offset: 0],
      load: [:display_name, :github_username, :hex_username, :avatar_url]
    )
  end

  defp role_value(nil), do: ""
  defp role_value(role), do: to_string(role)

  # The same names the select offers, for a row whose role is readable but not
  # editable. A role the viewer may not read at all reads as a dash rather than
  # as the absence of one.
  defp role_label(%Ash.ForbiddenField{}), do: "—"

  defp role_label(role), do: Enum.find_value(@roles, "—", &if(elem(&1, 1) == role, do: elem(&1, 0)))

  # Links to whichever hex instance we authenticate against, defaulting to
  # public hex.pm — a self-hosted one is the exception, and it sets base_url.
  defp hex_profile_url(username) do
    base_url = Keyword.get(Application.get_env(:varsel, :hex) || [], :base_url, "https://hex.pm")

    "#{String.trim_trailing(base_url, "/")}/users/#{username}"
  end

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
                <th>Hex.pm</th>
                <th class="text-right">Role</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={user <- @users.results} class="hover:bg-base-300/40">
                <td class="font-medium">
                  <span class="flex items-center gap-2">
                    <.avatar_disc user={user} />
                    {user.name || "—"}
                    <span :if={user.id == @current_user.id} class="badge badge-ghost badge-sm">
                      you
                    </span>
                  </span>
                </td>
                <td class="text-base-content/70">{user.notification_email || "—"}</td>
                <td>
                  <.link
                    :if={user.github_username}
                    href={"https://github.com/#{user.github_username}"}
                    class="link link-hover text-primary"
                    target="_blank"
                    rel="noopener"
                  >
                    @{user.github_username}
                  </.link>
                  <span :if={is_nil(user.github_username)} class="text-base-content/50">—</span>
                </td>
                <td>
                  <.link
                    :if={user.hex_username}
                    href={hex_profile_url(user.hex_username)}
                    class="link link-hover text-primary"
                    target="_blank"
                    rel="noopener"
                  >
                    @{user.hex_username}
                  </.link>
                  <span :if={is_nil(user.hex_username)} class="text-base-content/50">—</span>
                </td>
                <td class="text-right">
                  <form
                    :if={Accounts.can_set_user_role?(@current_user, user, %{})}
                    id={"role-#{user.id}"}
                    phx-change="set_role"
                    class="inline-block"
                  >
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
                  <%!-- Readable but not yours to change: the name of the role
                  rather than an empty cell where a control would be. --%>
                  <span
                    :if={!Accounts.can_set_user_role?(@current_user, user, %{})}
                    class="text-base-content/70"
                  >
                    {role_label(user.role)}
                  </span>
                </td>
                <td class="text-right">
                  <button
                    :if={Accounts.can_delete_user?(@current_user, user)}
                    type="button"
                    phx-click="delete_user"
                    phx-value-user_id={user.id}
                    data-confirm={delete_confirmation(user)}
                    class="btn btn-ghost btn-sm text-error"
                  >
                    Delete
                  </button>
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
