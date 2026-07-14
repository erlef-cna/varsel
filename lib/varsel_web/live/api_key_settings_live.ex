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
        {:noreply, assign(socket, form: form)}
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

  defp expires_at("never"), do: nil

  defp expires_at(days) do
    DateTime.add(DateTime.utc_now(), String.to_integer(days), :day)
  end

  defp format_date(nil), do: "never"
  defp format_date(datetime), do: Calendar.strftime(datetime, "%Y-%m-%d")

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-5xl py-10">
      <Layouts.flash_group flash={@flash} />

      <.header class="mb-6">
        API Tokens
        <:subtitle>
          Personal access tokens for the JSON:API, GraphQL and MCP endpoints. Pass them as
          <code class="text-xs">Authorization: Bearer &lt;token&gt;</code>
          headers.
        </:subtitle>
      </.header>

      <div :if={@created_key} class="alert alert-warning mb-6" role="alert">
        <.icon name="hero-key" class="size-5 shrink-0" />
        <div>
          <p class="font-medium">
            Copy your new token now — it won't be shown again.
          </p>
          <code class="select-all break-all text-sm">{elem(@created_key, 1)}</code>
        </div>
      </div>

      <.form
        for={@form}
        id="api-key-form"
        phx-submit="create"
        phx-change="validate"
        class="flex flex-wrap items-end gap-3 mb-8"
      >
        <.input
          field={@form[:name]}
          type="text"
          required
          placeholder="e.g. CI pipeline"
          class="input input-bordered input-sm w-56"
        >
          <:label>Name</:label>
        </.input>
        <label class="fieldset">
          <span class="label mb-1">Expires</span>
          <select name="expiry" class="select select-bordered select-sm">
            <option :for={{label, value} <- @expiry_presets} value={value} selected={value == @expiry}>
              {label}
            </option>
          </select>
        </label>
        <button type="submit" class="btn btn-primary btn-sm">Create token</button>
      </.form>

      <div class="overflow-x-auto">
        <table class="table table-zebra">
          <thead>
            <tr>
              <th>Name</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr :for={api_key <- @api_keys}>
              <td class="font-medium">{api_key.name}</td>
              <td>{format_date(api_key.inserted_at)}</td>
              <td>{format_date(api_key.expires_at)}</td>
              <td>
                <span :if={api_key.valid} class="badge badge-success badge-sm">active</span>
                <span :if={!api_key.valid} class="badge badge-ghost badge-sm">expired</span>
              </td>
              <td class="text-right">
                <button
                  phx-click="revoke"
                  phx-value-id={api_key.id}
                  data-confirm="Revoke this token? Applications using it will stop working."
                  class="btn btn-error btn-outline btn-xs"
                >
                  Revoke
                </button>
              </td>
            </tr>
            <tr :if={@api_keys == []}>
              <td colspan="5" class="text-center text-base-content/60">No tokens yet.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    """
  end
end
