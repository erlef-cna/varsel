# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseLifecycle do
  @moduledoc """
  What every case tab shares: the live case record, the tab list, and the
  lifecycle actions in the header.

  A tab calls `mount/3` once. That keeps the case record fresh from pub_sub,
  marks the case notifications read, and handles the lifecycle events its
  components push. Publish is the one lifecycle action that stays out: only
  the Publication tab shows it, next to the validation it depends on.
  """
  use VarselWeb, :html

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import Phoenix.LiveView, only: [attach_hook: 4, connected?: 1, push_navigate: 2, put_flash: 3]

  alias Phoenix.LiveView.Socket
  alias Varsel.Cases
  alias Varsel.CVE
  alias Varsel.Notifications

  @topics ~w(case case_proposal case_comment)

  @doc """
  Mounts the case on the socket as the `:case_record` assign and attaches
  the lifecycle event handlers.

  `load` names what to load on the case. `after_fetch` receives the loaded
  case and the socket after every fetch and returns the socket. A case the
  actor cannot read sends them back to the case list.
  """
  @spec mount(Socket.t(), String.t(), load: list(), after_fetch: fun()) ::
          Socket.t()
  def mount(socket, case_id, opts) do
    load = Keyword.fetch!(opts, :load)
    after_fetch = Keyword.fetch!(opts, :after_fetch)

    socket
    |> assign(case_id: case_id, cve_picker: nil)
    |> attach_hook(__MODULE__, :handle_event, &handle_event/3)
    |> keep_live(:case_record, &load_case(&1, load),
      subscribe: Enum.map(@topics, &"#{&1}:#{case_id}"),
      after_fetch: &fetched(&1, &2, after_fetch)
    )
  end

  @doc "The tabs of a case, in display order."
  def tabs(case_id) do
    [
      %{id: :workspace, label: "Workspace", navigate: ~p"/cases/#{case_id}"},
      %{id: :cve, label: "CVE", navigate: ~p"/cases/#{case_id}/cve"},
      %{id: :osv, label: "OSV", navigate: ~p"/cases/#{case_id}/osv"},
      %{id: :publication, label: "Publication", navigate: ~p"/cases/#{case_id}/publication"}
    ]
  end

  # The public page serves `:published` records only, so a link for any other
  # state would land on a 404.
  @doc "The public CVE page of the case, or nil while there is none."
  def public_cve_href(%{cve_id: cve_id, cve_record: %{state: :published}}) when is_binary(cve_id),
    do: ~p"/cves/#{cve_id <> ".html"}"

  def public_cve_href(_case_record), do: nil

  defp load_case(socket, load) do
    case Cases.get_case(socket.assigns.case_id, actor: socket.assigns.current_user, load: load) do
      {:ok, case_record} -> case_record
      {:error, _error} -> nil
    end
  end

  # nil: the case vanished or became inaccessible (on mount and refetch alike).
  defp fetched(nil, socket, _after_fetch) do
    socket |> put_flash(:error, "Case not found.") |> push_navigate(to: ~p"/cases")
  end

  defp fetched(case_record, socket, after_fetch) do
    if connected?(socket) do
      Notifications.mark_case_notifications_read!(case_record.id,
        actor: socket.assigns.current_user
      )
    end

    after_fetch.(case_record, socket)
  end

  ## ------------------------------------------------------------------ events

  defp handle_event("lifecycle", %{"action" => action}, socket)
       when action in ~w(request_review request_changes approve reopen) do
    fun =
      case action do
        "request_review" -> &Cases.request_case_review/2
        "request_changes" -> &Cases.request_case_changes/2
        "approve" -> &Cases.approve_case/2
        "reopen" -> &Cases.reopen_case/2
      end

    socket =
      case fun.(socket.assigns.case_record, actor: socket.assigns.current_user) do
        {:ok, _case_record} ->
          put_flash(socket, :info, "Case #{String.replace(action, "_", " ")}.")

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:halt, socket}
  end

  # Opening the picker reads the pool fresh: the ID list is the one thing on
  # this page that another POC can invalidate between page load and click.
  defp handle_event("assign_cve_id", _params, socket) do
    actor = socket.assigns.current_user

    {:halt, assign(socket, cve_picker: CVE.list_assignable_cve_records!(actor: actor))}
  end

  defp handle_event("cancel_cve_picker", _params, socket) do
    {:halt, assign(socket, :cve_picker, nil)}
  end

  # Both paths land here: "next free ID" sends no cve_record_id and lets the
  # action pick, a chosen row sends the one it names.
  defp handle_event("confirm_assign_cve_id", params, socket) do
    args =
      case params["cve_record_id"] do
        id when is_binary(id) and id != "" -> %{cve_record_id: id}
        _blank -> %{}
      end

    socket =
      case Cases.assign_case_cve_id(socket.assigns.case_record, args, actor: socket.assigns.current_user) do
        {:ok, case_record} ->
          assigned = Ash.load!(case_record, [:cve_id], actor: socket.assigns.current_user).cve_id

          socket
          |> assign(:cve_picker, nil)
          |> put_flash(:info, "Assigned #{assigned}.")

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:halt, socket}
  end

  defp handle_event("close_case", params, socket) do
    args = %{
      closed_reason: params["closed_reason"],
      reject_cve_id: params["cve_decision"] == "reject"
    }

    socket =
      case Cases.close_case(socket.assigns.case_record, args, actor: socket.assigns.current_user) do
        {:ok, _case_record} -> put_flash(socket, :info, "Case closed.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:halt, socket}
  end

  defp handle_event(_event, _params, socket), do: {:cont, socket}

  ## -------------------------------------------------------------- components

  @doc """
  Renders the lifecycle actions the actor may take on the case. Publish is
  not among them: the Publication tab renders it next to the validation.
  """
  attr :case_record, :map, required: true
  attr :current_user, :map, required: true

  def lifecycle_buttons(assigns) do
    ~H"""
    <div class="flex flex-wrap items-center gap-2">
      <button
        :if={Cases.can_assign_case_cve_id?(@current_user, @case_record, validate?: true)}
        class="btn btn-sm btn-eef-quiet"
        phx-click="assign_cve_id"
      >
        Assign CVE ID
      </button>
      <button
        :if={Cases.can_request_case_review?(@current_user, @case_record, validate?: true)}
        class="btn btn-sm btn-eef"
        phx-click="lifecycle"
        phx-value-action="request_review"
      >
        Request review
      </button>
      <button
        :if={Cases.can_request_case_changes?(@current_user, @case_record, validate?: true)}
        class="btn btn-sm btn-eef-quiet"
        phx-click="lifecycle"
        phx-value-action="request_changes"
      >
        Request changes
      </button>
      <button
        :if={Cases.can_approve_case?(@current_user, @case_record, validate?: true)}
        class="btn btn-sm btn-eef"
        phx-click="lifecycle"
        phx-value-action="approve"
      >
        Approve
      </button>
      <button
        :if={Cases.can_reopen_case?(@current_user, @case_record, validate?: true)}
        class="btn btn-ghost btn-sm"
        phx-click="lifecycle"
        phx-value-action="reopen"
      >
        Reopen
      </button>
    </div>
    """
  end

  @doc "Renders the collapsed close-case form."
  attr :case_record, :map, required: true

  def close_link(assigns) do
    ~H"""
    <details>
      <summary class="cursor-pointer text-xs text-base-content/50 hover:text-base-content/70">
        Close case
      </summary>
      <div class="mt-2 rounded-lg border border-base-300 bg-base-200 p-3">
        <form phx-submit="close_case" class="space-y-2">
          <input
            type="text"
            name="closed_reason"
            placeholder="Why is this case being closed?"
            class="input input-bordered input-sm w-full"
          />
          <div :if={@case_record.cve_id} class="text-sm space-y-1">
            <p class="font-semibold">{@case_record.cve_id} is assigned to this case:</p>
            <label class="flex items-center gap-2">
              <input type="radio" name="cve_decision" value="reject" class="radio radio-sm" required />
              Reject (burn) the CVE ID at MITRE
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" name="cve_decision" value="release" class="radio radio-sm" />
              Return the ID to the pool
            </label>
          </div>
          <button
            type="submit"
            class="btn btn-error btn-sm"
            data-confirm="Close this case? This is terminal."
          >
            Close case
          </button>
        </form>
      </div>
    </details>
    """
  end

  @doc """
  Renders the CVE ID picker for a case that has none.

  Two ways to take an ID, kept visibly apart: the top half is the one-click
  default (whatever is next in the pool), the bottom half is the deliberate
  pick. Nothing is assigned by opening this. Both halves need their own
  button, so neither path can be taken by reflex.

  Only a caller who may name a record can see the pool (the reservations are
  unreadable to anyone else), so for everyone else the listing is absent and
  the top half says nothing about what is in it. An empty `records` there
  means "not visible", not "not there".
  """
  attr :case_record, :map, required: true
  attr :current_user, :map, required: true
  attr :records, :list, required: true

  def cve_picker_modal(assigns) do
    {free, withheld} = Enum.split_with(assigns.records, &(&1.state == :reserved))

    can_choose? =
      Cases.can_assign_case_cve_id?(
        assigns.current_user,
        assigns.case_record,
        %{cve_record_id: Ash.UUID.generate()},
        validate?: false
      )

    assigns = assign(assigns, free: free, withheld: withheld, can_choose?: can_choose?)

    ~H"""
    <.modal id="cve-picker-modal" title="Assign a CVE ID" on_cancel="cancel_cve_picker">
      <div class="space-y-4">
        <div class="rounded-lg border border-base-300 bg-base-200 p-3">
          <p class="text-sm font-semibold">Take the next free ID</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            <span :if={!@can_choose? or @free != []}>
              The lowest free ID of the current year, chosen when you confirm.
            </span>
            <span :if={@can_choose? and @free == []}>
              The pool is empty — reserve more IDs first.
            </span>
          </p>
          <button
            :if={!@can_choose? or @free != []}
            type="button"
            class="btn btn-eef btn-sm mt-2"
            phx-click="confirm_assign_cve_id"
          >
            Assign the next free ID
          </button>
        </div>

        <form
          :if={@can_choose? and (@free != [] or @withheld != [])}
          phx-submit="confirm_assign_cve_id"
          class="rounded-lg border border-base-300 p-3"
        >
          <p class="text-sm font-semibold">Or choose a specific ID</p>
          <div class="mt-2 max-h-64 overflow-y-auto space-y-1">
            <label
              :for={record <- @free}
              class="flex items-center gap-2 py-0.5 cursor-pointer text-sm"
            >
              <input
                type="radio"
                name="cve_record_id"
                value={record.id}
                class="radio radio-sm"
                required
              />
              <span class="font-mono text-xs">{record.cve_id}</span>
              <span class="text-xs text-base-content/50 tabular-nums">
                reserved {format_date(record.reserved_at)}
              </span>
            </label>

            <%!-- Withheld IDs are held for something outside this system, so
                  they sit below a divider with the reason attached: taking one
                  should read as overriding a decision, not picking off a list. --%>
            <div
              :if={@withheld != []}
              class="flex items-center gap-2 pt-2 text-[0.66rem] font-semibold uppercase tracking-wider text-warning"
            >
              <span class="h-px flex-1 bg-warning/30"></span>
              withheld <span class="h-px flex-1 bg-warning/30"></span>
            </div>
            <label
              :for={record <- @withheld}
              class="flex items-start gap-2 py-1 px-2 -mx-1 rounded-md cursor-pointer text-sm bg-warning/10 border border-warning/25"
            >
              <input
                type="radio"
                name="cve_record_id"
                value={record.id}
                class="radio radio-sm radio-warning mt-0.5"
                required
              />
              <span class="flex flex-col">
                <span class="flex items-baseline gap-2">
                  <span class="font-mono text-xs">{record.cve_id}</span>
                  <span class="text-xs text-warning tabular-nums">
                    withheld {format_date(record.withheld_at)}
                  </span>
                </span>
                <span class="text-xs text-base-content/60">{record.withhold_reason}</span>
              </span>
            </label>
          </div>
          <button type="submit" class="btn btn-eef-quiet btn-sm mt-3">
            Assign chosen ID
          </button>
        </form>

        <p
          :if={@can_choose? and @free == [] and @withheld == []}
          class="text-sm text-base-content/60"
        >
          No CVE IDs are available to assign.
        </p>
      </div>

      <:actions>
        <button type="button" class="btn btn-ghost btn-sm" phx-click="cancel_cve_picker">
          Cancel
        </button>
      </:actions>
    </.modal>
    """
  end
end
