# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.NotificationSettingsLive do
  @moduledoc """
  Self-service notification preferences: email delivery mode and, per kind,
  whether it shows in the bell and whether it requests an email.

  The form always carries one row per `Varsel.Notifications.Kind` value, in
  enum order, seeded from `Varsel.Notifications.Preference.for_kind/2` so a
  kind the account has never touched still renders its (on, on) default.
  """
  use VarselWeb, :live_view

  alias Varsel.Notifications.EmailMode
  alias Varsel.Notifications.Kind
  alias Varsel.Notifications.Preference

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    user = socket.assigns[:current_user] || raise VarselWeb.UnauthorizedError

    {:ok,
     socket
     |> assign(page_title: "Notification settings", user: user, email_modes: email_modes())
     |> assign_form()}
  end

  defp email_modes, do: Enum.map(EmailMode.values(), &{EmailMode.label(&1), to_string(&1)})

  @impl Phoenix.LiveView
  def handle_event("validate", %{"form" => params}, socket) do
    {:noreply, assign(socket, form: AshPhoenix.Form.validate(socket.assigns.form, params))}
  end

  def handle_event("save", %{"form" => params}, socket) do
    case AshPhoenix.Form.submit(socket.assigns.form, params: params) do
      {:ok, user} ->
        {:noreply,
         socket
         |> assign(:user, user)
         |> assign_form()
         |> put_flash(:info, "Notification settings saved.")}

      {:error, form} ->
        {:noreply, assign(socket, :form, form)}
    end
  end

  defp assign_form(socket) do
    user = socket.assigns.user

    form =
      user
      |> AshPhoenix.Form.for_update(:update_notification_settings,
        as: "form",
        actor: user,
        forms: [auto?: true],
        params: %{
          "notification_email_mode" => to_string(user.notification_email_mode),
          "notification_preferences" => preference_params(user.notification_preferences)
        }
      )
      |> to_form()

    assign(socket, :form, form)
  end

  defp preference_params(preferences) do
    Enum.map(Kind.values(), fn kind ->
      preference = Preference.for_kind(preferences, kind)

      %{
        "kind" => to_string(kind),
        "in_app" => to_string(preference.in_app),
        "email" => to_string(preference.email)
      }
    end)
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
      <.page_header>
        <:eyebrow>CNA Console</:eyebrow>
        <:title>Notification settings</:title>
        <:subtitle>What the CNA notifies you about, and how.</:subtitle>
      </.page_header>

      <.page_container class="space-y-4">
        <.form for={@form} id="notification-settings-form" phx-change="validate" phx-submit="save">
          <.panel>
            <:title>Email delivery</:title>
            <.input field={@form[:notification_email_mode]} type="select" options={@email_modes}>
              <:label>When requested emails go out</:label>
            </.input>
          </.panel>

          <.panel class="mt-4">
            <:title>What to notify me about</:title>
            <div class="overflow-x-auto">
              <table class="table">
                <thead>
                  <tr>
                    <th>Event</th>
                    <th class="text-center">In app</th>
                    <th class="text-center">Email</th>
                  </tr>
                </thead>
                <tbody>
                  <.inputs_for :let={pref} field={@form[:notification_preferences]}>
                    <tr class="hover:bg-base-300/40">
                      <td>
                        <p class="font-medium">{Kind.label(pref[:kind].value)}</p>
                        <p class="text-xs text-base-content/60">
                          {Kind.description(pref[:kind].value)}
                        </p>
                      </td>
                      <td class="text-center">
                        <.input field={pref[:kind]} type="hidden" />
                        <.input field={pref[:in_app]} type="checkbox" />
                      </td>
                      <td class="text-center">
                        <.input field={pref[:email]} type="checkbox" />
                      </td>
                    </tr>
                  </.inputs_for>
                </tbody>
              </table>
            </div>
          </.panel>

          <div class="mt-4 flex justify-end">
            <button type="submit" class="btn btn-eef btn-sm">Save</button>
          </div>
        </.form>
      </.page_container>
    </Layouts.app>
    """
  end
end
