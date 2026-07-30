# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
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

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]

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

  def handle_event("paginate", %{"page" => target}, socket) do
    {:noreply, change_page(socket, :api_keys, target)}
  end

  def handle_event("jump_page", %{"page" => target}, socket) do
    {:noreply, jump_to_page(socket, :api_keys, target)}
  end

  def handle_event("revoke", %{"id" => id}, socket) do
    actor = socket.assigns.current_user
    api_key = Enum.find(socket.assigns.api_keys.results, &(&1.id == id))

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
    keep_live(socket, :api_keys, &list_api_keys/2, results: :lose)
  end

  # The keep_live callback: page_opts is nil on the first run and the stored
  # page's options on a refetch, so a revoke keeps the page the user is on.
  defp list_api_keys(socket, page_opts) do
    Accounts.list_api_keys!(
      actor: socket.assigns.current_user,
      query: Ash.Query.sort(ApiKey, inserted_at: :desc),
      load: [:valid],
      page: page_opts || [count: true, offset: 0]
    )
  end

  defp form_errors(form) do
    form.source
    |> AshPhoenix.Form.errors()
    |> Enum.map_join("; ", fn {field, message} -> "#{field} #{message}" end)
  end

  defp expires_at("never"), do: nil

  defp expires_at(days) do
    DateTime.shift(DateTime.utc_now(), day: String.to_integer(days))
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <.page_header>
      <:eyebrow>CNA Console</:eyebrow>
      <:title>API Tokens</:title>
      <:subtitle>Personal access tokens for the GraphQL and MCP endpoints.</:subtitle>
    </.page_header>

    <.page_container class="space-y-4">
      <div class="rounded-box border border-base-300 p-4">
        <h2 class="font-semibold">Create a token</h2>
        <p class="text-sm text-base-content/60 mt-0.5 mb-3">
          The token authenticates API requests as you — send it as an
          <code class="font-mono text-xs">Authorization: Bearer</code>
          header. It is shown exactly once, right after creation.
        </p>
        <.form
          :if={Accounts.can_create_api_key?(@current_user, %{})}
          for={@form}
          id="api-key-form"
          phx-submit="create"
          phx-change="validate"
          class="flex flex-wrap items-start gap-2 [&_.fieldset]:mb-0"
        >
          <.input
            field={@form[:name]}
            type="text"
            required
            placeholder="Token name, e.g. CI pipeline"
            class="input input-bordered input-sm w-64"
          />
          <.input
            name="expiry"
            type="select"
            value={@expiry}
            options={@expiry_presets}
            class="select select-bordered select-sm w-32"
          />
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

      <.list_card empty?={@api_keys.results == []}>
        <:empty>No tokens yet — create one above.</:empty>
        <:footer :if={paged?(@api_keys)}>
          <.pagination page={@api_keys} noun="token" />
        </:footer>

        <div class="overflow-x-auto">
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
              <tr :for={api_key <- @api_keys.results} class="hover:bg-base-300/40">
                <td class="font-medium">{api_key.name}</td>
                <td>
                  <.state :if={api_key.valid} dot="bg-success">Active</.state>
                  <.state :if={!api_key.valid} dot="bg-base-content/30">Expired</.state>
                </td>
                <td class="whitespace-nowrap tabular-nums text-base-content/70">
                  {format_date(api_key.inserted_at, "never")}
                </td>
                <td class="whitespace-nowrap tabular-nums text-base-content/70">
                  {format_date(api_key.expires_at, "never")}
                </td>
                <td class="text-right">
                  <button
                    :if={Accounts.can_revoke_api_key?(@current_user, api_key)}
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
      </.list_card>
    </.page_container>
    """
  end
end
