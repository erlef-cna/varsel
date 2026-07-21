# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ApiKeySettingsLive do
  @moduledoc """
  Self-service API token management for any logged-in user.

  Access is gated by the `:live_user_required` on_mount hook; the policies on
  `Varsel.Accounts.ApiKey` scope every query and mutation to the
  current user's own keys. The plaintext key only exists in the action
  result's metadata and is rendered exactly once after creation.
  """
  use VarselWeb, :live_view

  alias Varsel.Accounts
  alias Varsel.Accounts.ApiKey

  @expiry_presets [
    {"30 days", "30"},
    {"90 days", "90"},
    {"1 year", "365"},
    {"Never", "never"}
  ]

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(
        page_title: "API Tokens",
        expiry_presets: @expiry_presets,
        created_key: nil,
        expiry: "30"
      )
      |> assign_form()
      |> assign_api_keys()

    {:ok, socket}
  end

  @impl Phoenix.LiveView
  def handle_event("validate", %{"form" => params} = raw, socket) do
    socket = assign(socket, expiry: raw["expiry"] || socket.assigns.expiry)
    {:noreply, assign(socket, form: AshPhoenix.Form.validate(socket.assigns.form, params))}
  end

  @impl Phoenix.LiveView
  def handle_event("create", %{"form" => params} = raw, socket) do
    params = Map.put(params, "expires_at", expires_at(raw["expiry"]))

    case AshPhoenix.Form.submit(socket.assigns.form, params: params) do
      {:ok, api_key} ->
        {:noreply,
         socket
         |> assign(created_key: {api_key, api_key.__metadata__.plaintext_api_key}, expiry: "30")
         |> assign_form()
         |> assign_api_keys()
         |> put_flash(:info, "Token #{api_key.name} created.")}

      {:error, form} ->
        {:noreply,
         socket
         |> assign(form: form)
         |> put_flash(:error, "Could not create the token: #{form_errors(form)}")}
    end
  end

  def handle_event("revoke", %{"id" => id}, socket) do
    actor = socket.assigns.current_user
    api_key = Enum.find(socket.assigns.api_keys, &(&1.id == id))

    socket =
      case Accounts.revoke_api_key(api_key, actor: actor) do
        :ok ->
          socket
          |> assign_api_keys()
          |> put_flash(:info, "Token #{api_key.name} revoked.")

        {:error, _error} ->
          put_flash(socket, :error, "Could not revoke token #{api_key.name}.")
      end

    {:noreply, socket}
  end

  defp assign_form(socket) do
    form =
      ApiKey
      |> AshPhoenix.Form.for_create(:create, as: "form", actor: socket.assigns.current_user)
      |> to_form()

    assign(socket, :form, form)
  end

  defp assign_api_keys(socket) do
    api_keys =
      [actor: socket.assigns.current_user, load: [:valid]]
      |> Accounts.list_api_keys!()
      |> Enum.sort_by(& &1.inserted_at, {:desc, DateTime})

    assign(socket, api_keys: api_keys)
  end

  defp form_errors(form) do
    form.source
    |> AshPhoenix.Form.errors()
    |> Enum.map_join("; ", fn {field, message} -> "#{field} #{message}" end)
  end

  defp expires_at("never"), do: nil

  defp expires_at(days) do
    DateTime.add(DateTime.utc_now(), String.to_integer(days), :day)
  end

  defp format_date(nil), do: "never"
  defp format_date(datetime), do: Calendar.strftime(datetime, "%Y-%m-%d")

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <.console_header
      title="API Tokens"
      subtitle="Personal access tokens for the GraphQL and MCP endpoints."
    />

    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-6 space-y-4">
      <div class="rounded-box border border-base-300 p-4">
        <h2 class="font-semibold">Create a token</h2>
        <p class="text-sm text-base-content/60 mt-0.5 mb-3">
          The token authenticates API requests as you — send it as an
          <code class="font-mono text-xs">Authorization: Bearer</code>
          header. It is shown exactly once, right after creation.
        </p>
        <.form
          for={@form}
          id="api-key-form"
          phx-submit="create"
          phx-change="validate"
          class="flex flex-wrap items-center gap-2"
        >
          <input
            type="text"
            name={@form[:name].name}
            value={@form[:name].value}
            required
            placeholder="Token name, e.g. CI pipeline"
            class="input input-bordered input-sm w-64"
          />
          <select name="expiry" class="select select-bordered select-sm w-32">
            <option :for={{label, value} <- @expiry_presets} value={value} selected={value == @expiry}>
              {label}
            </option>
          </select>
          <button type="submit" class="btn btn-sm btn-eef">Create token</button>
        </.form>
      </div>

      <div :if={@created_key} class="alert alert-warning" role="alert">
        <.icon name="hero-key" class="size-5 shrink-0" />
        <div>
          <p class="font-medium">
            Copy your new token now — it won't be shown again.
          </p>
          <code class="select-all break-all text-sm">{elem(@created_key, 1)}</code>
        </div>
      </div>

      <div class="rounded-box border border-base-300 overflow-hidden">
        <div class="px-4 py-2.5 border-b border-base-300 text-sm text-base-content/70 tabular-nums">
          {if length(@api_keys) == 1, do: "1 token", else: "#{length(@api_keys)} tokens"}
        </div>

        <div :if={@api_keys != []} class="overflow-x-auto">
          <table class="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>Created</th>
                <th>Expires</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={api_key <- @api_keys} class="hover:bg-base-200">
                <td class="font-medium">{api_key.name}</td>
                <td>
                  <.state :if={api_key.valid} dot="bg-success">Active</.state>
                  <.state :if={!api_key.valid} dot="bg-base-content/30">Expired</.state>
                </td>
                <td class="whitespace-nowrap tabular-nums text-base-content/70">
                  {format_date(api_key.inserted_at)}
                </td>
                <td class="whitespace-nowrap tabular-nums text-base-content/70">
                  {format_date(api_key.expires_at)}
                </td>
                <td class="text-right">
                  <button
                    phx-click="revoke"
                    phx-value-id={api_key.id}
                    data-confirm="Revoke this token? Applications using it will stop working."
                    class="link link-hover text-error/80 text-sm"
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <p :if={@api_keys == []} class="text-center text-base-content/60 py-8">
          No tokens yet — create one above.
        </p>
      </div>
    </div>
    """
  end
end
