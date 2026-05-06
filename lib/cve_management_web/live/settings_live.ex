# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.SettingsLive do
  @moduledoc false
  use CveManagementWeb, :live_view

  on_mount {CveManagementWeb.LiveUserAuth, :live_user_required}

  def render(assigns) do
    ~H"""
    <div class="container mx-auto p-6">
      <h1 class="text-2xl font-bold mb-6">Settings</h1>

      <section class="mb-8">
        <h2 class="text-xl font-semibold mb-2">GitHub App Connection</h2>
        <p class="text-sm text-gray-600 mb-4">
          Connect the GitHub App to allow fetching GitHub Security Advisories on your behalf.
          Requires <code>security_events</code> and <code>notifications</code> scopes.
        </p>

        <%= if @github_token_status == :connected do %>
          <p class="text-green-600 font-medium mb-2">Connected</p>
          <div class="flex gap-2">
            <.link href={~p"/auth/github_app"} class="btn btn-outline btn-sm">
              Reconnect GitHub App
            </.link>
            <button phx-click="disconnect_github_app" class="btn btn-error btn-sm">
              Disconnect
            </button>
          </div>
        <% else %>
          <%= if @github_token_status == :invalid do %>
            <p class="text-red-600 font-medium mb-2">
              Connection invalid — please reconnect.
            </p>
            <div class="flex gap-2">
              <.link href={~p"/auth/github_app"} class="btn btn-primary btn-sm">
                Reconnect GitHub App
              </.link>
              <button phx-click="disconnect_github_app" class="btn btn-error btn-sm">
                Disconnect
              </button>
            </div>
          <% else %>
            <.link href={~p"/auth/github_app"} class="btn btn-primary btn-sm">
              Connect GitHub App
            </.link>
          <% end %>
        <% end %>
      </section>
    </div>
    """
  end

  def mount(_params, _session, socket) do
    user = socket.assigns.current_user

    {status, token} =
      case Ash.get(CveManagement.Accounts.GitHubAppToken, [user_id: user.id],
             actor: user,
             domain: CveManagement.Accounts
           ) do
        {:ok, %{status: :valid} = token} -> {:connected, token}
        {:ok, %{status: :invalid} = token} -> {:invalid, token}
        _ -> {:not_connected, nil}
      end

    {:ok, assign(socket, github_token_status: status, github_token: token)}
  end

  def handle_event("disconnect_github_app", _params, socket) do
    user = socket.assigns.current_user
    token = socket.assigns.github_token

    case Ash.destroy(token, action: :disconnect, actor: user) do
      :ok ->
        {:noreply,
         socket
         |> put_flash(:info, "GitHub App disconnected.")
         |> assign(github_token_status: :not_connected, github_token: nil)}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to disconnect GitHub App.")}
    end
  end
end
