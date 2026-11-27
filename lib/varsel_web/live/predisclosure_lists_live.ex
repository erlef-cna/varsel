# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.PredisclosureListsLive do
  @moduledoc """
  POC management of pre-disclosure lists: create, rename and delete lists,
  and choose who subscribes to each. Cases go on lists from the case page.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.UserComponents, only: [user_badge: 1, user_picker: 1]

  alias Varsel.Accounts
  alias Varsel.Predisclosure
  alias Varsel.Predisclosure.ListSubscriber
  alias Varsel.Predisclosure.PredisclosureList

  @picker_limit 8
  @user_fields [:display_name, :avatar_url, :github_username, :hex_username, :role]

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    {:ok, socket}
  end

  @impl Phoenix.LiveView
  def handle_params(%{"id" => id}, _uri, socket) do
    socket =
      socket
      |> assign(list_id: id, picker: nil)
      |> keep_live(:list, &load_list/1, subscribe: "predisclosure_list:#{id}")
      |> assign_rename_form()

    {:noreply, assign(socket, page_title: socket.assigns.list.name)}
  end

  def handle_params(_params, _uri, socket) do
    socket =
      socket
      |> assign(page_title: "Pre-disclosure lists")
      |> keep_live(:lists, &list_lists/1, subscribe: "predisclosure_list:all")
      |> assign_create_form()

    {:noreply, socket}
  end

  @impl Phoenix.LiveView
  def handle_event("validate_create", %{"form" => params}, socket) do
    {:noreply, assign(socket, create_form: AshPhoenix.Form.validate(socket.assigns.create_form, params))}
  end

  def handle_event("create", %{"form" => params}, socket) do
    case AshPhoenix.Form.submit(socket.assigns.create_form, params: params) do
      {:ok, list} -> {:noreply, push_navigate(socket, to: ~p"/predisclosure-lists/#{list.id}")}
      {:error, form} -> {:noreply, assign(socket, create_form: form)}
    end
  end

  def handle_event("validate_rename", %{"form" => params}, socket) do
    {:noreply, assign(socket, rename_form: AshPhoenix.Form.validate(socket.assigns.rename_form, params))}
  end

  def handle_event("rename", %{"form" => params}, socket) do
    case AshPhoenix.Form.submit(socket.assigns.rename_form, params: params) do
      {:ok, _list} -> {:noreply, put_flash(socket, :info, "List renamed.")}
      {:error, form} -> {:noreply, assign(socket, rename_form: form)}
    end
  end

  def handle_event("delete", _params, socket) do
    case Predisclosure.destroy_predisclosure_list(socket.assigns.list,
           actor: socket.assigns.current_user
         ) do
      :ok ->
        {:noreply,
         socket
         |> put_flash(:info, "Deleted #{socket.assigns.list.name}.")
         |> push_navigate(to: ~p"/predisclosure-lists")}

      {:error, _error} ->
        {:noreply, put_flash(socket, :error, "Could not delete the list.")}
    end
  end

  def handle_event("open_picker", _params, socket) do
    {:noreply, assign(socket, picker: search(socket, ""))}
  end

  def handle_event("close_picker", _params, socket) do
    {:noreply, assign(socket, picker: nil)}
  end

  def handle_event("search_subscriber", params, socket) do
    {:noreply, assign(socket, picker: search(socket, params["query"], params["user_id"]))}
  end

  def handle_event("subscribe", %{"user_id" => user_id}, socket) do
    actor = socket.assigns.current_user

    socket =
      case Predisclosure.subscribe_to_predisclosure_list(socket.assigns.list.id, user_id, actor: actor) do
        {:ok, _subscriber} -> assign(socket, picker: nil)
        {:error, _error} -> put_flash(socket, :error, "Could not add the subscriber.")
      end

    {:noreply, socket}
  end

  def handle_event("unsubscribe", %{"row_id" => id}, socket) do
    subscriber = Enum.find(socket.assigns.list.subscribers, &(&1.id == id))

    socket =
      case Predisclosure.unsubscribe_from_predisclosure_list(subscriber,
             actor: socket.assigns.current_user
           ) do
        :ok -> socket
        {:error, _error} -> put_flash(socket, :error, "Could not remove the subscriber.")
      end

    {:noreply, socket}
  end

  defp list_lists(socket) do
    Predisclosure.list_predisclosure_lists!(
      actor: socket.assigns.current_user,
      load: [:subscriber_count, :case_count]
    )
  end

  defp load_list(socket) do
    Predisclosure.get_predisclosure_list!(socket.assigns.list_id,
      actor: socket.assigns.current_user,
      load: [subscribers: [user: @user_fields]]
    )
  end

  defp assign_create_form(socket) do
    form =
      PredisclosureList
      |> AshPhoenix.Form.for_create(:create, as: "form", actor: socket.assigns.current_user)
      |> to_form()

    assign(socket, create_form: form)
  end

  defp assign_rename_form(socket) do
    form =
      socket.assigns.list
      |> AshPhoenix.Form.for_update(:rename, as: "form", actor: socket.assigns.current_user)
      |> to_form()

    assign(socket, rename_form: form)
  end

  defp search(socket, query, selected \\ nil) do
    query = String.trim(query || "")
    exclude_ids = Enum.map(socket.assigns.list.subscribers, & &1.user_id)

    {users, rest} =
      query
      |> Accounts.search_users!(%{exclude_ids: exclude_ids},
        actor: socket.assigns.current_user,
        query: [limit: @picker_limit + 1],
        load: @user_fields
      )
      |> Enum.split(@picker_limit)

    %{
      query: query,
      users: users,
      more?: rest != [],
      selected: Enum.find_value(users, &(&1.id == selected && selected))
    }
  end

  @impl Phoenix.LiveView
  def render(%{live_action: :show} = assigns) do
    ~H"""
    <Layouts.app
      flash={@flash}
      current_user={@current_user}
      current_path={@current_path}
      socket={@socket}
    >
      <.page_header>
        <:eyebrow>
          <.link navigate={~p"/predisclosure-lists"} class="link link-hover">Pre-disclosure lists</.link>
        </:eyebrow>
        <:title>{@list.name}</:title>
        <:subtitle>
          Subscribers see every case on this list: they read it, comment and propose changes.
        </:subtitle>
        <:actions>
          <button
            :if={Predisclosure.can_destroy_predisclosure_list?(@current_user, @list)}
            id="delete-list"
            class="btn btn-sm btn-ghost text-error"
            phx-click="delete"
            data-confirm={"Delete #{@list.name}? Its subscribers lose access to the cases it holds."}
          >
            Delete list
          </button>
        </:actions>
      </.page_header>

      <.page_container class="space-y-4">
        <.panel :if={Predisclosure.can_rename_predisclosure_list?(@current_user, @list, @list.name)}>
          <:title>Name</:title>
          <.form
            for={@rename_form}
            id="rename-list-form"
            phx-change="validate_rename"
            phx-submit="rename"
            class="flex flex-wrap items-start gap-2 [&_.fieldset]:mb-0"
          >
            <.input
              field={@rename_form[:name]}
              type="text"
              required
              class="input input-bordered input-sm w-72"
            />
            <button type="submit" class="btn btn-sm btn-eef-quiet">Rename</button>
          </.form>
        </.panel>

        <.panel>
          <:title>Subscribers</:title>
          <:actions>
            <button
              :if={!@picker and Ash.can?({ListSubscriber, :subscribe}, @current_user)}
              id="add-subscriber"
              class="link link-hover text-primary"
              phx-click="open_picker"
            >
              Add subscriber
            </button>
          </:actions>

          <form
            :if={@picker}
            id="subscriber-picker-form"
            phx-change="search_subscriber"
            phx-submit="subscribe"
            class="mb-3 space-y-2 rounded-lg border border-base-300 bg-base-200 p-3"
          >
            <.user_picker
              id="subscriber-picker"
              query={@picker.query}
              users={@picker.users}
              selected={@picker.selected}
              more?={@picker.more?}
            />
            <div class="flex gap-2">
              <button type="submit" class="btn btn-sm btn-eef">Add</button>
              <button type="button" class="btn btn-sm btn-ghost" phx-click="close_picker">Cancel</button>
            </div>
          </form>

          <ul id="list-subscribers" class="space-y-2 text-sm">
            <li
              :for={subscriber <- Enum.sort_by(@list.subscribers, & &1.user.display_name)}
              id={"subscriber-#{subscriber.id}"}
              class="flex items-center justify-between gap-2"
            >
              <.user_badge user={subscriber.user} name_class="truncate" />
              <button
                :if={
                  Predisclosure.can_unsubscribe_from_predisclosure_list?(@current_user, subscriber)
                }
                class="btn btn-ghost btn-xs text-error"
                phx-click="unsubscribe"
                phx-value-row_id={subscriber.id}
                data-confirm="Take this user off the list? They lose access to its cases."
              >
                Remove
              </button>
            </li>
          </ul>
          <p :if={@list.subscribers == []} class="text-sm text-base-content/60">
            No subscribers yet.
          </p>
        </.panel>
      </.page_container>
    </Layouts.app>
    """
  end

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
        <:title>Pre-disclosure lists</:title>
        <:subtitle>
          Groups of people who see the cases you share with them before publication.
        </:subtitle>
      </.page_header>

      <.page_container class="space-y-4">
        <div
          :if={Ash.can?({PredisclosureList, :create}, @current_user)}
          class="rounded-box border border-base-300 p-4"
        >
          <h2 class="font-semibold">Create a list</h2>
          <.form
            for={@create_form}
            id="create-list-form"
            phx-change="validate_create"
            phx-submit="create"
            class="mt-3 flex flex-wrap items-start gap-2 [&_.fieldset]:mb-0"
          >
            <.input
              field={@create_form[:name]}
              type="text"
              required
              placeholder="List name, e.g. Linux distributions"
              class="input input-bordered input-sm w-72"
            />
            <button type="submit" class="btn btn-sm btn-eef">Create list</button>
          </.form>
        </div>

        <.list_card empty?={@lists == []}>
          <:empty>No lists yet.</:empty>
          <div class="overflow-x-auto">
            <table id="predisclosure-lists" class="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th class="text-right">Subscribers</th>
                  <th class="text-right">Cases</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={list <- @lists} id={"list-#{list.id}"}>
                  <td>
                    <.link
                      navigate={~p"/predisclosure-lists/#{list.id}"}
                      class="link link-hover font-medium"
                    >
                      {list.name}
                    </.link>
                  </td>
                  <td class="text-right tabular-nums">{list.subscriber_count}</td>
                  <td class="text-right tabular-nums">{list.case_count}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </.list_card>
      </.page_container>
    </Layouts.app>
    """
  end
end
