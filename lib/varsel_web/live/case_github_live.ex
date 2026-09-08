# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseGitHubLive do
  @moduledoc """
  The GitHub tab of a case: the security advisory it is linked to, read as
  the person looking, and the case set against it field by field.
  """
  use VarselWeb, :live_view

  import VarselWeb.AdvisoryComponents
  import VarselWeb.CaseComponents, only: [case_header: 1]

  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.GitHub.UserToken
  alias VarselWeb.CaseLifecycle

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    socket =
      socket
      |> assign(busy?: false, github_identity?: UserToken.linked?(socket.assigns.current_user))
      |> CaseLifecycle.mount(id,
        load: [:cve_id, :cve_record, github_advisory_link: [:diff]],
        after_fetch: &after_fetch/2
      )

    {:ok, socket}
  end

  defp after_fetch(case_record, socket) do
    actor = socket.assigns.current_user
    link = case_record.github_advisory_link

    socket
    |> assign(page_title: case_record.title || "Case", link: link)
    |> assign(permissions(actor, case_record, link))
    |> assign_form(link)
  end

  # A create cannot be asked about before its row exists, so the case's own
  # edit action, which the link's create defers to, answers for linking.
  defp permissions(actor, case_record, nil) do
    %{
      can_link?: Cases.can_edit_case?(actor, case_record, %{}, validate?: true),
      can_unlink?: false,
      can_refresh?: false,
      can_pull?: false,
      can_push?: false
    }
  end

  defp permissions(actor, _case_record, link) do
    %{
      can_link?: false,
      can_unlink?: Cases.can_unlink_github_advisory?(actor, link, %{}, validate?: true),
      can_refresh?: Cases.can_refresh_github_advisory_link?(actor, link, %{}, validate?: true),
      can_pull?: Cases.can_pull_github_advisory?(actor, link, [:title], %{}, validate?: true),
      can_push?: Cases.can_push_github_advisory?(actor, link, [:title], %{}, validate?: true)
    }
  end

  # A notification on the case refetches it while the viewer types, so the
  # form they are filling in stays.
  defp assign_form(%{assigns: %{form: %{}}} = socket, nil), do: socket

  defp assign_form(socket, nil) do
    form =
      GitHubAdvisoryLink
      |> AshPhoenix.Form.for_create(:link, as: "form", actor: socket.assigns.current_user)
      |> to_form()

    assign(socket, form: form)
  end

  defp assign_form(socket, _link), do: assign(socket, form: nil)

  defp link_params(socket, params), do: Map.put(params, "case_id", socket.assigns.case_record.id)

  @impl Phoenix.LiveView
  def handle_event("validate", %{"form" => params}, socket) do
    form = AshPhoenix.Form.validate(socket.assigns.form, link_params(socket, params))
    {:noreply, assign(socket, form: form)}
  end

  def handle_event("link_advisory", %{"form" => params}, socket) do
    case AshPhoenix.Form.submit(socket.assigns.form, params: link_params(socket, params)) do
      {:ok, link} -> {:noreply, put_flash(socket, :info, "Linked #{link.ghsa_id}.")}
      {:error, form} -> {:noreply, assign(socket, form: form)}
    end
  end

  def handle_event(event, _params, %{assigns: %{busy?: true}} = socket)
      when event in ["refresh_advisory", "push_advisory"] do
    {:noreply, socket}
  end

  def handle_event("refresh_advisory", _params, socket) do
    %{link: link, current_user: actor} = socket.assigns

    {:noreply,
     socket
     |> assign(busy?: true)
     |> start_async(:refresh, fn -> Cases.refresh_github_advisory_link(link, actor: actor) end)}
  end

  def handle_event("pull_advisory", %{"fields" => fields}, socket) do
    %{link: link, current_user: actor} = socket.assigns
    fields = String.split(fields, ",", trim: true)

    socket =
      case Cases.pull_github_advisory(link, fields, actor: actor) do
        {:ok, _link} ->
          put_flash(
            socket,
            :info,
            "Pulled #{Enum.map_join(fields, ", ", &field_label/1)} from the advisory."
          )

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_event("push_advisory", %{"fields" => fields}, socket) do
    %{link: link, current_user: actor} = socket.assigns
    fields = String.split(fields, ",", trim: true)

    {:noreply,
     socket
     |> assign(busy?: true)
     |> start_async(:push, fn -> Cases.push_github_advisory(link, fields, actor: actor) end)}
  end

  def handle_event("unlink_advisory", _params, socket) do
    %{link: link, current_user: actor} = socket.assigns

    socket =
      case Cases.unlink_github_advisory(link, actor: actor) do
        :ok -> put_flash(socket, :info, "Unlinked #{link.ghsa_id}.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  @impl Phoenix.LiveView
  def handle_async(:refresh, {:ok, result}, socket) do
    socket =
      case result do
        {:ok, _link} -> put_flash(socket, :info, "Advisory read again.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, assign(socket, busy?: false)}
  end

  def handle_async(:push, {:ok, result}, socket) do
    socket =
      case result do
        {:ok, %{__metadata__: %{skipped_credits: [_credit | _rest] = skipped}}} ->
          put_flash(
            socket,
            :info,
            "Pushed to the advisory. Not stated, having no GitHub account here: #{Enum.join(skipped, ", ")}."
          )

        {:ok, _link} ->
          put_flash(socket, :info, "Pushed to the advisory.")

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, assign(socket, busy?: false)}
  end

  def handle_async(task, {:exit, reason}, socket) when task in [:refresh, :push] do
    {:noreply,
     socket
     |> assign(busy?: false)
     |> put_flash(:error, "GitHub request failed: #{Exception.format_exit(reason)}")}
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
      <.case_header
        case_record={@case_record}
        public_href={CaseLifecycle.public_cve_href(@case_record)}
        tabs={CaseLifecycle.tabs(@case_record.id)}
        active={@live_action}
      >
        <:actions>
          <CaseLifecycle.lifecycle_buttons case_record={@case_record} current_user={@current_user} />
        </:actions>
      </.case_header>

      <.page_container width={:wide} class="space-y-4">
        <div :if={!@github_identity?} id="github-identity-notice" class="alert alert-info text-sm">
          <.icon name="hero-information-circle" class="size-5 shrink-0" />
          <span>
            Draft advisories are read and written with your GitHub account, and none is linked
            to yours.
            <.link navigate={~p"/settings/account"} class="link link-hover font-semibold">
              Link GitHub in account settings
            </.link>
            to refresh and push from here.
          </span>
        </div>

        <%= if @link do %>
          <.advisory_card
            link={@link}
            can_refresh={@github_identity? and @can_refresh?}
            can_unlink={@can_unlink?}
            busy={@busy?}
          />
          <.advisory_diff
            rows={@link.diff}
            can_pull={@can_pull?}
            can_push={@github_identity? and @can_push?}
            busy={@busy?}
          />
        <% else %>
          <.panel id="link-advisory">
            <:title>GitHub advisory</:title>
            <div :if={@can_link?}>
              <p class="text-sm text-base-content/60 mb-3">
                Link the GitHub security advisory this case is about. It leads the published
                references as the vendor advisory, and this tab sets the case against it.
              </p>
              <.form
                for={@form}
                id="link-advisory-form"
                phx-submit="link_advisory"
                phx-change="validate"
                class="flex flex-wrap items-start gap-2 [&_.fieldset]:mb-0 [&_.fieldset]:grow"
              >
                <.input
                  field={@form[:advisory_url]}
                  type="text"
                  required
                  placeholder="https://github.com/owner/repo/security/advisories/GHSA-…"
                  class="input input-bordered input-sm w-full"
                />
                <button type="submit" class="btn btn-sm btn-eef">Link</button>
              </.form>
            </div>
            <.empty_state :if={!@can_link?} class="py-4">
              No advisory is linked to this case.
            </.empty_state>
          </.panel>
        <% end %>
      </.page_container>

      <CaseLifecycle.cve_picker_modal
        :if={@cve_picker}
        case_record={@case_record}
        current_user={@current_user}
        records={@cve_picker}
      />
    </Layouts.app>
    """
  end
end
