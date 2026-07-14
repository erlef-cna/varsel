# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseDetailLive do
  @moduledoc """
  The case workspace: edit case content, manage affected packages (channels
  and version boundary facts), references, credits and classifications,
  review proposals, discuss in comments, walk the lifecycle, and preview the
  rendered CVE record.

  Content edits follow the content freeze (draft/review only); lifecycle
  decisions are POC-only — the same policies the API enforces, mirrored here
  only to hide dead buttons. Child rows are added/edited through one modal
  `AshPhoenix.Form` at a time; per-row actions stay raw.
  """
  use VarselWeb, :live_view

  alias Varsel.Accounts
  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseImpact
  alias Varsel.Cases.CaseReference
  alias Varsel.Cases.CaseWeakness
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.VersionEvent

  @case_loads [
    :cve_id,
    assignments: [:user],
    references: [],
    credits: [],
    weaknesses: [:weakness],
    impacts: [:attack_pattern],
    affected_packages: [:channels, :version_events],
    proposals: [:author, :resolved_by],
    comments: [:author]
  ]

  # Modal child-form registry: UI type -> resource + labels. Every resource
  # has an :add create action; those with `edit?` also have an :edit update.
  @children %{
    "package" => %{resource: AffectedPackage, title: "affected package", edit?: true},
    "channel" => %{resource: PackageChannel, title: "distribution channel", edit?: true},
    "event" => %{resource: VersionEvent, title: "version boundary", edit?: true},
    "reference" => %{resource: CaseReference, title: "reference", edit?: true},
    "credit" => %{resource: CaseCredit, title: "credit", edit?: true},
    "weakness" => %{resource: CaseWeakness, title: "CWE classification", edit?: false},
    "impact" => %{resource: CaseImpact, title: "CAPEC classification", edit?: false}
  }

  # Comma/newline separated text inputs that become {:array, :string} attributes.
  @list_params %{
    "package" => ~w(modules program_files program_routines platforms),
    "channel" => ~w(tag_suffixes),
    "reference" => ~w(tags)
  }

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    case Cases.get_case(id, actor: socket.assigns.current_user, load: @case_loads) do
      {:ok, case_record} ->
        if connected?(socket), do: subscribe(id)

        {:ok,
         socket
         |> assign(case_id: id, child_form: nil, preview: nil, users: nil)
         |> assign_case(case_record)}

      {:error, _error} ->
        {:ok,
         socket
         |> put_flash(:error, "Case not found.")
         |> push_navigate(to: ~p"/cases")}
    end
  end

  defp subscribe(case_id) do
    for topic <- ["case:#{case_id}", "case_proposal:#{case_id}", "case_comment:#{case_id}"] do
      Phoenix.PubSub.subscribe(Varsel.PubSub, topic)
    end
  end

  @impl Phoenix.LiveView
  def handle_info(%Phoenix.Socket.Broadcast{payload: %Ash.Notifier.Notification{}}, socket) do
    {:noreply, reload_case(socket)}
  end

  ## ------------------------------------------------------------ case content

  @impl Phoenix.LiveView
  def handle_event("validate", %{"form" => params}, socket) do
    {:noreply, assign(socket, content_form: AshPhoenix.Form.validate(socket.assigns.content_form, params))}
  end

  def handle_event("save", %{"form" => params} = raw, socket) do
    case decode_override(raw["cna_override_json"]) do
      {:ok, override} ->
        params = Map.put(params, "cna_override", override)

        case AshPhoenix.Form.submit(socket.assigns.content_form, params: params) do
          {:ok, _case_record} ->
            {:noreply, socket |> put_flash(:info, "Case saved.") |> reload_case()}

          {:error, form} ->
            {:noreply, assign(socket, content_form: form)}
        end

      :error ->
        {:noreply, put_flash(socket, :error, "The CNA override must be valid JSON.")}
    end
  end

  ## --------------------------------------------------------------- lifecycle

  # Publishing refreshes derivations (git fetches); run it off the LiveView.
  def handle_event("lifecycle", %{"action" => "publish"}, socket) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    {:noreply,
     socket
     |> put_flash(:info, "Publishing — rendering and validating the record…")
     |> start_async(:publish, fn -> Cases.publish_case(case_record, actor: actor) end)}
  end

  def handle_event("lifecycle", %{"action" => action}, socket) do
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
          socket |> put_flash(:info, "Case #{humanize_action(action)}.") |> reload_case()

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_event("assign_cve_id", _params, socket) do
    socket =
      case Cases.assign_case_cve_id(socket.assigns.case_record, %{}, actor: socket.assigns.current_user) do
        {:ok, _case_record} -> socket |> put_flash(:info, "CVE ID assigned.") |> reload_case()
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_event("close_case", params, socket) do
    args = %{
      closed_reason: params["closed_reason"],
      reject_cve_id: params["cve_decision"] == "reject",
      acknowledge_parked_cve_id: params["cve_decision"] == "park"
    }

    socket =
      case Cases.close_case(socket.assigns.case_record, args, actor: socket.assigns.current_user) do
        {:ok, _case_record} -> socket |> put_flash(:info, "Case closed.") |> reload_case()
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_event("refresh_derivation", _params, socket) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    {:noreply,
     socket
     |> assign(preview: :loading)
     |> start_async(:preview, fn ->
       {:ok, _} = Cases.refresh_case_derivation(case_record, actor: actor)
       Cases.render_case_preview!(%{id: case_record.id}, actor: actor)
     end)}
  end

  def handle_event("preview", _params, socket) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    {:noreply,
     socket
     |> assign(preview: :loading)
     |> start_async(:preview, fn ->
       Cases.render_case_preview!(%{id: case_record.id}, actor: actor)
     end)}
  end

  def handle_event("close_preview", _params, socket) do
    {:noreply, assign(socket, preview: nil)}
  end

  ## -------------------------------------------------------------- child rows

  def handle_event("new_child", %{"type" => type} = params, socket) do
    %{resource: resource, title: title} = Map.fetch!(@children, type)

    form =
      resource
      |> AshPhoenix.Form.for_create(:add, as: "child", actor: socket.assigns.current_user)
      |> to_form()

    parent =
      params
      |> Map.take(["affected_package_id"])
      |> Map.put("case_id", socket.assigns.case_record.id)

    {:noreply, assign(socket, child_form: %{form: form, type: type, title: "Add #{title}", parent: parent})}
  end

  def handle_event("edit_child", %{"type" => type, "id" => id}, socket) do
    %{resource: resource, title: title} = Map.fetch!(@children, type)
    row = Ash.get!(resource, id, actor: socket.assigns.current_user)

    form =
      row
      |> AshPhoenix.Form.for_update(:edit, as: "child", actor: socket.assigns.current_user)
      |> to_form()

    {:noreply, assign(socket, child_form: %{form: form, type: type, title: "Edit #{title}", parent: %{}})}
  end

  def handle_event("validate_child", %{"child" => params}, socket) do
    %{form: form, type: type} = socket.assigns.child_form
    params = normalize_child_params(type, params, socket.assigns.child_form.parent)
    form = AshPhoenix.Form.validate(form, params)

    {:noreply, assign(socket, child_form: %{socket.assigns.child_form | form: form})}
  end

  def handle_event("submit_child", %{"child" => params}, socket) do
    %{form: form, type: type} = socket.assigns.child_form
    params = normalize_child_params(type, params, socket.assigns.child_form.parent)

    case AshPhoenix.Form.submit(form, params: params) do
      {:ok, _row} ->
        {:noreply, socket |> assign(child_form: nil) |> put_flash(:info, "Saved.") |> reload_case()}

      {:error, form} ->
        {:noreply, assign(socket, child_form: %{socket.assigns.child_form | form: form})}
    end
  end

  def handle_event("cancel_child", _params, socket) do
    {:noreply, assign(socket, child_form: nil)}
  end

  def handle_event("remove_child", %{"type" => type, "id" => id}, socket) do
    %{resource: resource} = Map.fetch!(@children, type)
    actor = socket.assigns.current_user

    socket =
      with {:ok, row} <- Ash.get(resource, id, actor: actor),
           :ok <- Ash.destroy(row, action: :remove, actor: actor) do
        socket |> put_flash(:info, "Removed.") |> reload_case()
      else
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  ## ------------------------------------------------------------- assignments

  def handle_event("assign_user", %{"user_id" => user_id}, socket) do
    socket =
      case Cases.assign_case_user(
             %{case_id: socket.assigns.case_record.id, user_id: user_id},
             actor: socket.assigns.current_user
           ) do
        {:ok, _assignment} -> socket |> put_flash(:info, "User assigned.") |> reload_case()
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_event("unassign_user", %{"id" => id}, socket) do
    assignment = Enum.find(socket.assigns.case_record.assignments, &(&1.id == id))

    socket =
      case Cases.unassign_case_user(assignment, actor: socket.assigns.current_user) do
        :ok -> socket |> put_flash(:info, "User unassigned.") |> reload_case()
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  ## --------------------------------------------------------------- proposals

  # One form per proposal with two submit buttons; the clicked button's
  # name/value pair selects the decision.
  def handle_event("resolve_proposal", %{"proposal_id" => id, "decision" => decision} = params, socket) do
    {fun, verb} =
      case decision do
        "accept" -> {&Cases.accept_case_proposal/3, "accepted"}
        "decline" -> {&Cases.decline_case_proposal/3, "declined"}
      end

    resolve_proposal(socket, id, params["resolution_note"], fun, verb)
  end

  def handle_event("withdraw_proposal", %{"id" => id}, socket) do
    proposal = Enum.find(socket.assigns.case_record.proposals, &(&1.id == id))

    socket =
      case Cases.withdraw_case_proposal(proposal, actor: socket.assigns.current_user) do
        {:ok, _proposal} -> socket |> put_flash(:info, "Proposal withdrawn.") |> reload_case()
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  ## ---------------------------------------------------------------- comments

  def handle_event("post_comment", %{"body" => body} = params, socket) do
    attrs = %{
      case_id: socket.assigns.case_record.id,
      body: body,
      proposal_id: presence(params["proposal_id"])
    }

    socket =
      case Cases.post_case_comment(attrs, actor: socket.assigns.current_user) do
        {:ok, _comment} -> reload_case(socket)
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  @impl Phoenix.LiveView
  def handle_async(:preview, {:ok, preview}, socket) do
    {:noreply, socket |> assign(preview: preview) |> reload_case()}
  end

  def handle_async(:preview, {:exit, reason}, socket) do
    {:noreply,
     socket
     |> assign(preview: nil)
     |> put_flash(:error, "Preview failed: #{Exception.format_exit(reason)}")}
  end

  def handle_async(:publish, {:ok, result}, socket) do
    socket =
      case result do
        {:ok, _case_record} ->
          socket |> put_flash(:info, "Publish handed to MITRE.") |> reload_case()

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_async(:publish, {:exit, reason}, socket) do
    {:noreply, put_flash(socket, :error, "Publish failed: #{Exception.format_exit(reason)}")}
  end

  ## ----------------------------------------------------------------- helpers

  defp resolve_proposal(socket, id, note, fun, verb) do
    proposal = Enum.find(socket.assigns.case_record.proposals, &(&1.id == id))
    args = %{resolution_note: presence(note)}

    socket =
      case fun.(proposal, args, actor: socket.assigns.current_user) do
        {:ok, _proposal} -> socket |> put_flash(:info, "Proposal #{verb}.") |> reload_case()
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  defp assign_case(socket, case_record) do
    actor = socket.assigns.current_user

    content_form =
      if editable?(case_record) do
        case_record
        |> AshPhoenix.Form.for_update(:edit, as: "form", actor: actor)
        |> to_form()
      end

    users =
      if poc?(actor) do
        Accounts.list_users!(actor: actor)
      else
        []
      end

    assign(socket,
      case_record: case_record,
      content_form: content_form,
      users: users,
      page_title: case_record.title || "Case"
    )
  end

  defp reload_case(socket) do
    case Cases.get_case(socket.assigns.case_id,
           actor: socket.assigns.current_user,
           load: @case_loads
         ) do
      {:ok, case_record} -> assign_case(socket, case_record)
      {:error, _error} -> push_navigate(socket, to: ~p"/cases")
    end
  end

  # Splits comma/newline separated list inputs and merges the parent ids.
  defp normalize_child_params(type, params, parent) do
    params = Map.merge(params, parent)

    Enum.reduce(Map.get(@list_params, type, []), params, fn key, params ->
      case params[key] do
        value when is_binary(value) ->
          Map.put(
            params,
            key,
            value |> String.split(~r/[\n,]/, trim: true) |> Enum.map(&String.trim/1)
          )

        _other ->
          params
      end
    end)
  end

  defp decode_override(nil), do: {:ok, nil}

  defp decode_override(json) do
    case String.trim(json) do
      "" ->
        {:ok, nil}

      trimmed ->
        case Jason.decode(trimmed) do
          {:ok, override} when is_map(override) -> {:ok, override}
          _other -> :error
        end
    end
  end

  defp presence(nil), do: nil

  defp presence(value) when is_binary(value), do: if(String.trim(value) == "", do: nil, else: value)

  defp errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  defp poc?(%{role: :poc}), do: true
  defp poc?(_user), do: false

  defp assigned?(case_record, %{id: user_id}), do: Enum.any?(case_record.assignments, &(&1.user_id == user_id))

  defp editable?(case_record), do: case_record.state in [:draft, :review]

  defp can_edit?(case_record, user), do: editable?(case_record) and (poc?(user) or assigned?(case_record, user))

  @doc "DaisyUI badge class for a case state."
  def state_badge_class(:draft), do: "badge-warning"
  def state_badge_class(:review), do: "badge-info"
  def state_badge_class(:approved), do: "badge-accent"
  def state_badge_class(:publishing), do: "badge-info"
  def state_badge_class(:published), do: "badge-success"
  def state_badge_class(:closed), do: "badge-neutral"
  def state_badge_class(_other), do: "badge-ghost"

  defp proposal_badge_class(:open), do: "badge-warning"
  defp proposal_badge_class(:accepted), do: "badge-success"
  defp proposal_badge_class(:declined), do: "badge-error"
  defp proposal_badge_class(_other), do: "badge-ghost"

  defp humanize_action(action), do: String.replace(action, "_", " ")

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")

  defp pretty_json(nil), do: ""
  defp pretty_json(value), do: Jason.encode!(value, pretty: true)

  defp enum_options(enum), do: Enum.map(enum.values(), &{&1 |> to_string() |> String.replace("_", " "), &1})

  defp proposal_summary(proposal) do
    target = proposal.target |> to_string() |> String.replace("_", " ")

    case proposal.operation do
      :set -> "set #{target}.#{proposal.field_name}"
      :insert -> "add #{target}"
      :delete -> "remove #{target}"
    end
  end

  ## ------------------------------------------------------------------ render

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-10">
      <Layouts.flash_group flash={@flash} />

      <.header class="mb-6">
        {@case_record.title || "Untitled case"}
        <:subtitle>
          <span class={["badge badge-sm mr-2", state_badge_class(@case_record.state)]}>
            {@case_record.state}
          </span>
          <span :if={@case_record.cve_id} class="font-mono">{@case_record.cve_id}</span>
          <span :if={is_nil(@case_record.cve_id)} class="text-base-content/60">no CVE ID assigned</span>
        </:subtitle>
        <:actions>
          <.lifecycle_buttons case_record={@case_record} current_user={@current_user} />
        </:actions>
      </.header>

      <div class="grid lg:grid-cols-3 gap-8">
        <div class="lg:col-span-2 space-y-8">
          <.content_section
            case_record={@case_record}
            content_form={@content_form}
            can_edit={can_edit?(@case_record, @current_user)}
          />
          <.affected_section
            case_record={@case_record}
            can_edit={can_edit?(@case_record, @current_user)}
          />
          <.rows_section
            id="references"
            heading="References"
            type="reference"
            add_label="Add reference"
            rows={@case_record.references}
            can_edit={can_edit?(@case_record, @current_user)}
          >
            <:row :let={reference}>
              <span class="font-mono text-sm break-all">{reference.url}</span>
              <span :for={tag <- reference.tags} class="badge badge-ghost badge-xs ml-1">{tag}</span>
            </:row>
          </.rows_section>
          <.rows_section
            id="credits"
            heading="Credits"
            type="credit"
            add_label="Add credit"
            rows={@case_record.credits}
            can_edit={can_edit?(@case_record, @current_user)}
          >
            <:row :let={credit}>
              {credit.name}{if credit.organization, do: " / #{credit.organization}"}
              <span class="badge badge-ghost badge-xs ml-1">
                {credit.credit_type |> to_string() |> String.replace("_", " ")}
              </span>
            </:row>
          </.rows_section>
          <.rows_section
            id="weaknesses"
            heading="Weaknesses (CWE)"
            type="weakness"
            add_label="Add CWE"
            rows={@case_record.weaknesses}
            can_edit={can_edit?(@case_record, @current_user)}
          >
            <:row :let={weakness}>
              <span class="font-mono">CWE-{weakness.cwe_id}</span> {weakness.weakness.name}
            </:row>
          </.rows_section>
          <.rows_section
            id="impacts"
            heading="Impacts (CAPEC)"
            type="impact"
            add_label="Add CAPEC"
            rows={@case_record.impacts}
            can_edit={can_edit?(@case_record, @current_user)}
          >
            <:row :let={impact}>
              <span class="font-mono">CAPEC-{impact.capec_id}</span> {impact.attack_pattern.name}
            </:row>
          </.rows_section>
        </div>

        <div class="space-y-8">
          <.preview_section preview={@preview} />
          <.proposals_section
            case_record={@case_record}
            current_user={@current_user}
            can_resolve={can_edit?(@case_record, @current_user)}
          />
          <.comments_section case_record={@case_record} />
          <.assignments_section :if={poc?(@current_user)} case_record={@case_record} users={@users} />
          <.close_section
            :if={poc?(@current_user) and editable?(@case_record)}
            case_record={@case_record}
          />
        </div>
      </div>

      <.child_modal :if={@child_form} child_form={@child_form} />
    </div>
    """
  end

  defp lifecycle_buttons(assigns) do
    ~H"""
    <div class="flex flex-wrap items-center gap-2">
      <button
        :if={
          @case_record.state in [:draft, :review, :approved] and is_nil(@case_record.cve_id) and
            poc?(@current_user)
        }
        class="btn btn-outline btn-sm"
        phx-click="assign_cve_id"
      >
        Assign CVE ID
      </button>
      <button
        :if={@case_record.state == :draft}
        class="btn btn-primary btn-sm"
        phx-click="lifecycle"
        phx-value-action="request_review"
      >
        Request review
      </button>
      <button
        :if={@case_record.state == :review and poc?(@current_user)}
        class="btn btn-outline btn-sm"
        phx-click="lifecycle"
        phx-value-action="request_changes"
      >
        Request changes
      </button>
      <button
        :if={@case_record.state == :review and poc?(@current_user)}
        class="btn btn-primary btn-sm"
        phx-click="lifecycle"
        phx-value-action="approve"
      >
        Approve
      </button>
      <button
        :if={@case_record.state == :approved and poc?(@current_user)}
        class="btn btn-primary btn-sm"
        phx-click="lifecycle"
        phx-value-action="publish"
        data-confirm="Publish this case to MITRE?"
      >
        Publish
      </button>
      <button
        :if={@case_record.state in [:review, :approved, :published] and poc?(@current_user)}
        class="btn btn-ghost btn-sm"
        phx-click="lifecycle"
        phx-value-action="reopen"
      >
        Reopen
      </button>
    </div>
    """
  end

  defp content_section(assigns) do
    ~H"""
    <section>
      <h2 class="text-lg font-semibold mb-3">Case content</h2>

      <.form
        :if={@can_edit and @content_form}
        for={@content_form}
        id="case-content-form"
        phx-change="validate"
        phx-submit="save"
      >
        <.input field={@content_form[:title]} type="text">
          <:label>Title</:label>
        </.input>
        <.input
          field={@content_form[:description_md]}
          type="textarea"
          rows="8"
          class="w-full textarea font-mono text-sm"
        >
          <:label>Description (Markdown)</:label>
        </.input>
        <.input
          field={@content_form[:workarounds_md]}
          type="textarea"
          rows="3"
          class="w-full textarea font-mono text-sm"
        >
          <:label>Workarounds (Markdown, optional)</:label>
        </.input>
        <.input
          field={@content_form[:configurations_md]}
          type="textarea"
          rows="3"
          class="w-full textarea font-mono text-sm"
        >
          <:label>Configurations (Markdown, optional)</:label>
        </.input>
        <.input
          field={@content_form[:solutions_md]}
          type="textarea"
          rows="3"
          class="w-full textarea font-mono text-sm"
        >
          <:label>Solutions (Markdown, optional)</:label>
        </.input>
        <div class="grid sm:grid-cols-2 gap-x-4">
          <.input
            field={@content_form[:cvss_v4]}
            type="text"
            placeholder="CVSS:4.0/AV:N/…"
            class="w-full input font-mono"
          >
            <:label>CVSS v4.0 vector</:label>
          </.input>
          <.input
            field={@content_form[:discovery]}
            type="select"
            options={enum_options(Varsel.Cases.Case.Discovery)}
          >
            <:label>Discovery</:label>
          </.input>
        </div>
        <.input
          field={@content_form[:internal_notes]}
          type="textarea"
          rows="2"
          class="w-full textarea text-sm"
        >
          <:label>Internal notes (never published)</:label>
        </.input>

        <details class="mt-2">
          <summary class="cursor-pointer text-sm text-base-content/60">
            Advanced: CNA override
          </summary>
          <label class="label mt-2 text-sm">
            RFC 7396 JSON Merge Patch applied to the rendered CNA container
          </label>
          <textarea name="cna_override_json" rows="4" class="w-full textarea font-mono text-sm">{pretty_json(@case_record.cna_override)}</textarea>
        </details>

        <button type="submit" class="btn btn-primary btn-sm mt-4">Save</button>
      </.form>

      <div :if={not @can_edit} class="prose max-w-none">
        <p :if={@case_record.description_md} class="whitespace-pre-wrap">
          {@case_record.description_md}
        </p>
        <p :if={is_nil(@case_record.description_md)} class="text-base-content/60">
          No description yet.
        </p>
        <p :if={@case_record.cvss_v4} class="font-mono text-sm">{@case_record.cvss_v4.vector}</p>
        <p :if={not editable?(@case_record)} class="text-sm text-base-content/60">
          Content is frozen in the {@case_record.state} state; reopen the case to edit it.
        </p>
      </div>
    </section>
    """
  end

  defp affected_section(assigns) do
    ~H"""
    <section>
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-lg font-semibold">Affected packages</h2>
        <div class="flex gap-2">
          <button class="btn btn-ghost btn-xs" phx-click="refresh_derivation">Refresh derivation</button>
          <button
            :if={@can_edit}
            class="btn btn-outline btn-xs"
            phx-click="new_child"
            phx-value-type="package"
          >
            Add package
          </button>
        </div>
      </div>

      <div :for={package <- @case_record.affected_packages} class="card bg-base-200 mb-4">
        <div class="card-body p-4">
          <div class="flex items-start justify-between">
            <div>
              <h3 class="font-semibold">{package.vendor} / {package.product}</h3>
              <p :if={package.repo_url} class="text-sm font-mono text-base-content/70">
                {package.repo_url}
              </p>
              <p class="text-xs text-base-content/60 mt-1">
                default status: {package.default_status}
                <span :if={package.allow_unreleased_fix}>· allows unreleased fixes</span>
              </p>
            </div>
            <div :if={@can_edit} class="flex gap-1">
              <button
                class="btn btn-ghost btn-xs"
                phx-click="edit_child"
                phx-value-type="package"
                phx-value-id={package.id}
              >
                Edit
              </button>
              <button
                class="btn btn-ghost btn-xs text-error"
                phx-click="remove_child"
                phx-value-type="package"
                phx-value-id={package.id}
                data-confirm="Remove this package with all its channels and boundary facts?"
              >
                Remove
              </button>
            </div>
          </div>

          <div class="mt-2">
            <div class="flex items-center justify-between">
              <h4 class="text-sm font-semibold text-base-content/70">Channels</h4>
              <button
                :if={@can_edit}
                class="btn btn-ghost btn-xs"
                phx-click="new_child"
                phx-value-type="channel"
                phx-value-affected_package_id={package.id}
              >
                Add channel
              </button>
            </div>
            <table :if={package.channels != []} class="table table-xs">
              <tbody>
                <tr :for={channel <- package.channels}>
                  <td><span class="badge badge-ghost badge-sm">{channel.channel_type}</span></td>
                  <td class="font-mono">{channel.package_name || "—"}</td>
                  <td class="text-xs text-base-content/60">
                    {if channel.versions_override, do: "versions overridden"}
                    {if channel.entry_override, do: "entry overridden"}
                  </td>
                  <td :if={@can_edit} class="text-right whitespace-nowrap">
                    <button
                      class="btn btn-ghost btn-xs"
                      phx-click="edit_child"
                      phx-value-type="channel"
                      phx-value-id={channel.id}
                    >
                      Edit
                    </button>
                    <button
                      class="btn btn-ghost btn-xs text-error"
                      phx-click="remove_child"
                      phx-value-type="channel"
                      phx-value-id={channel.id}
                      data-confirm="Remove this channel?"
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p :if={package.channels == []} class="text-sm text-base-content/60">No channels yet.</p>
          </div>

          <div class="mt-2">
            <div class="flex items-center justify-between">
              <h4 class="text-sm font-semibold text-base-content/70">Version boundaries</h4>
              <button
                :if={@can_edit}
                class="btn btn-ghost btn-xs"
                phx-click="new_child"
                phx-value-type="event"
                phx-value-affected_package_id={package.id}
              >
                Add boundary
              </button>
            </div>
            <table :if={package.version_events != []} class="table table-xs">
              <tbody>
                <tr :for={event <- package.version_events}>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      if(event.event == :fixed, do: "badge-success", else: "badge-warning")
                    ]}>
                      {event.event}
                    </span>
                  </td>
                  <td class="font-mono text-xs break-all">{event.commit_sha || event.version}</td>
                  <td class="text-xs text-base-content/60">{event.note}</td>
                  <td :if={@can_edit} class="text-right whitespace-nowrap">
                    <button
                      class="btn btn-ghost btn-xs"
                      phx-click="edit_child"
                      phx-value-type="event"
                      phx-value-id={event.id}
                    >
                      Edit
                    </button>
                    <button
                      class="btn btn-ghost btn-xs text-error"
                      phx-click="remove_child"
                      phx-value-type="event"
                      phx-value-id={event.id}
                      data-confirm="Remove this boundary fact?"
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p :if={package.version_events == []} class="text-sm text-base-content/60">
              No boundary facts yet (introduced/fixed commits or versions).
            </p>
          </div>
        </div>
      </div>

      <p :if={@case_record.affected_packages == []} class="text-sm text-base-content/60">
        No affected packages yet.
      </p>
    </section>
    """
  end

  attr :id, :string, required: true
  attr :heading, :string, required: true
  attr :type, :string, required: true
  attr :add_label, :string, required: true
  attr :rows, :list, required: true
  attr :can_edit, :boolean, required: true
  slot :row, required: true

  defp rows_section(assigns) do
    ~H"""
    <section id={@id}>
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-lg font-semibold">{@heading}</h2>
        <button
          :if={@can_edit}
          class="btn btn-outline btn-xs"
          phx-click="new_child"
          phx-value-type={@type}
        >
          {@add_label}
        </button>
      </div>
      <ul class="space-y-1">
        <li
          :for={row <- @rows}
          class="flex items-center justify-between gap-2 py-1 border-b border-base-200"
        >
          <div>{render_slot(@row, row)}</div>
          <div :if={@can_edit} class="flex gap-1 shrink-0">
            <button
              :if={@type in ["reference", "credit"]}
              class="btn btn-ghost btn-xs"
              phx-click="edit_child"
              phx-value-type={@type}
              phx-value-id={row.id}
            >
              Edit
            </button>
            <button
              class="btn btn-ghost btn-xs text-error"
              phx-click="remove_child"
              phx-value-type={@type}
              phx-value-id={row.id}
              data-confirm="Remove?"
            >
              Remove
            </button>
          </div>
        </li>
      </ul>
      <p :if={@rows == []} class="text-sm text-base-content/60">None yet.</p>
    </section>
    """
  end

  defp preview_section(assigns) do
    ~H"""
    <section>
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-lg font-semibold">Record preview</h2>
        <button class="btn btn-outline btn-xs" phx-click="preview" disabled={@preview == :loading}>
          {if @preview == :loading, do: "Rendering…", else: "Render preview"}
        </button>
      </div>

      <div :if={is_map(@preview)} class="space-y-3">
        <div :if={@preview["blockers"] != []} class="alert alert-warning text-sm block">
          <p class="font-semibold">Publish blockers</p>
          <ul class="list-disc list-inside">
            <li :for={blocker <- @preview["blockers"]}>{blocker}</li>
          </ul>
        </div>

        <div :if={@preview["validation"]} class="text-sm">
          <span :if={@preview["validation"][:valid]} class="badge badge-success badge-sm">record valid</span>
          <div :if={@preview["validation"][:valid] == false} class="alert alert-error text-sm block">
            <p class="font-semibold">Validation errors</p>
            <ul class="list-disc list-inside">
              <li :for={error <- @preview["validation"][:errors]}>{error.source}: {error.message}</li>
            </ul>
          </div>
        </div>

        <div :if={@preview["overrides_applied"] != []} class="text-xs text-base-content/60">
          Overrides applied: {Enum.join(@preview["overrides_applied"], ", ")}
        </div>

        <details>
          <summary class="cursor-pointer text-sm">CNA container JSON</summary>
          <pre class="bg-base-200 rounded p-3 text-xs overflow-x-auto max-h-96">{pretty_json(@preview["cna"])}</pre>
        </details>

        <button class="btn btn-ghost btn-xs" phx-click="close_preview">Close preview</button>
      </div>
    </section>
    """
  end

  defp proposals_section(assigns) do
    ~H"""
    <section>
      <h2 class="text-lg font-semibold mb-3">Proposals</h2>

      <div :for={proposal <- @case_record.proposals} class="card bg-base-200 mb-3">
        <div class="card-body p-3 text-sm">
          <div class="flex items-center justify-between">
            <span class="font-semibold">{proposal_summary(proposal)}</span>
            <span class={["badge badge-sm", proposal_badge_class(proposal.state)]}>{proposal.state}</span>
          </div>

          <pre
            :if={proposal.proposed_value}
            class="bg-base-300 rounded p-2 text-xs overflow-x-auto max-h-40"
          >{pretty_json(proposal.proposed_value["value"])}</pre>

          <p :if={proposal.reasoning} class="text-base-content/80 whitespace-pre-wrap">
            {proposal.reasoning}
          </p>

          <p class="text-xs text-base-content/60">
            by {proposal.author.name || proposal.author.email} · {format_dt(proposal.inserted_at)}
            <span :if={proposal.resolved_by}>
              · resolved by {proposal.resolved_by.name || proposal.resolved_by.email}
            </span>
          </p>

          <p :if={proposal.resolution_note} class="text-xs text-base-content/60 italic">
            {proposal.resolution_note}
          </p>

          <form
            :if={proposal.state == :open and @can_resolve}
            phx-submit="resolve_proposal"
            id={"resolve-#{proposal.id}"}
            class="flex items-center gap-1 mt-1"
          >
            <input type="hidden" name="proposal_id" value={proposal.id} />
            <input
              type="text"
              name="resolution_note"
              placeholder="Note (optional)"
              class="input input-bordered input-xs flex-1"
            />
            <button type="submit" name="decision" value="accept" class="btn btn-success btn-xs">
              Accept
            </button>
            <button type="submit" name="decision" value="decline" class="btn btn-error btn-xs">
              Decline
            </button>
          </form>

          <button
            :if={proposal.state == :open and proposal.author_id == @current_user.id}
            class="btn btn-ghost btn-xs self-start"
            phx-click="withdraw_proposal"
            phx-value-id={proposal.id}
          >
            Withdraw
          </button>
        </div>
      </div>

      <p :if={@case_record.proposals == []} class="text-sm text-base-content/60">No proposals.</p>
    </section>
    """
  end

  defp comments_section(assigns) do
    ~H"""
    <section>
      <h2 class="text-lg font-semibold mb-3">Comments</h2>

      <div :for={comment <- @case_record.comments} class="mb-3 text-sm">
        <p class="text-xs text-base-content/60">
          {comment.author.name || comment.author.email} · {format_dt(comment.inserted_at)}
          <span :if={comment.proposal_id} class="badge badge-ghost badge-xs">on proposal</span>
        </p>
        <p class="whitespace-pre-wrap">{comment.body}</p>
      </div>

      <p :if={@case_record.comments == []} class="text-sm text-base-content/60">No comments yet.</p>

      <form phx-submit="post_comment" class="mt-3">
        <textarea
          name="body"
          rows="2"
          required
          placeholder="Write a comment…"
          class="w-full textarea text-sm"
        ></textarea>
        <button type="submit" class="btn btn-outline btn-xs mt-1">Comment</button>
      </form>
    </section>
    """
  end

  defp assignments_section(assigns) do
    ~H"""
    <section>
      <h2 class="text-lg font-semibold mb-3">Assignments</h2>

      <ul class="space-y-1 text-sm">
        <li :for={assignment <- @case_record.assignments} class="flex items-center justify-between">
          <span>{assignment.user.name || assignment.user.email}</span>
          <button
            class="btn btn-ghost btn-xs text-error"
            phx-click="unassign_user"
            phx-value-id={assignment.id}
            data-confirm="Revoke this user's access to the case?"
          >
            Remove
          </button>
        </li>
      </ul>

      <form phx-submit="assign_user" class="flex items-center gap-2 mt-2">
        <select name="user_id" required class="select select-bordered select-sm flex-1">
          <option value="">Assign a user…</option>
          <option
            :for={user <- @users}
            :if={not Enum.any?(@case_record.assignments, &(&1.user_id == user.id))}
            value={user.id}
          >
            {user.name || user.email}
          </option>
        </select>
        <button type="submit" class="btn btn-outline btn-sm">Assign</button>
      </form>
    </section>
    """
  end

  defp close_section(assigns) do
    ~H"""
    <section>
      <details>
        <summary class="cursor-pointer text-sm font-semibold text-error">Close case</summary>
        <form phx-submit="close_case" class="mt-2 space-y-2">
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
              <input type="radio" name="cve_decision" value="park" class="radio radio-sm" />
              Keep the ID parked at MITRE
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
      </details>
    </section>
    """
  end

  defp child_modal(assigns) do
    ~H"""
    <div class="modal modal-open" id="child-modal">
      <div class="modal-box max-w-lg">
        <h3 class="font-semibold text-lg mb-3">{@child_form.title}</h3>

        <.form
          for={@child_form.form}
          id="child-form"
          phx-change="validate_child"
          phx-submit="submit_child"
        >
          <.child_fields type={@child_form.type} form={@child_form.form} />

          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" phx-click="cancel_child">Cancel</button>
            <button type="submit" class="btn btn-primary btn-sm">Save</button>
          </div>
        </.form>
      </div>
      <div class="modal-backdrop" phx-click="cancel_child"></div>
    </div>
    """
  end

  defp child_fields(%{type: "package"} = assigns) do
    ~H"""
    <div class="grid sm:grid-cols-2 gap-x-4">
      <.input field={@form[:vendor]} type="text">
        <:label>Vendor</:label>
      </.input>
      <.input field={@form[:product]} type="text">
        <:label>Product</:label>
      </.input>
    </div>
    <.input field={@form[:repo_url]} type="text" placeholder="https://github.com/owner/repo">
      <:label>Repository URL (empty for hosted services)</:label>
    </.input>
    <.input
      field={@form[:default_status]}
      type="select"
      options={enum_options(AffectedPackage.DefaultStatus)}
    >
      <:label>Default status</:label>
    </.input>
    <.input field={@form[:modules]} type="text" value={list_value(@form[:modules])}>
      <:label>Modules (comma separated)</:label>
    </.input>
    <.input field={@form[:program_files]} type="text" value={list_value(@form[:program_files])}>
      <:label>Program files (comma separated)</:label>
    </.input>
    <.input field={@form[:program_routines]} type="text" value={list_value(@form[:program_routines])}>
      <:label>Program routines, Erlang notation (comma separated)</:label>
    </.input>
    <.input
      field={@form[:cpe]}
      type="text"
      placeholder="derived from vendor/product when empty"
      class="w-full input font-mono"
    >
      <:label>CPE 2.3 (optional override)</:label>
    </.input>
    <.input field={@form[:allow_unreleased_fix]} type="checkbox">
      <:label>Allow publishing while a fix has no containing release</:label>
    </.input>
    """
  end

  defp child_fields(%{type: "channel"} = assigns) do
    ~H"""
    <.input
      field={@form[:channel_type]}
      type="select"
      options={enum_options(PackageChannel.ChannelType)}
    >
      <:label>Channel type</:label>
    </.input>
    <.input field={@form[:package_name]} type="text" placeholder="e.g. my_package or owner/repo">
      <:label>Package name (empty only for hosted)</:label>
    </.input>
    <.input field={@form[:registry_url]} type="text" placeholder="e.g. ghcr.io/owner">
      <:label>Registry URL (OCI/npm only)</:label>
    </.input>
    <.input field={@form[:tag_suffixes]} type="text" value={list_value(@form[:tag_suffixes])}>
      <:label>OCI tag suffixes (comma separated)</:label>
    </.input>
    <.input field={@form[:position]} type="number">
      <:label>Position</:label>
    </.input>
    """
  end

  defp child_fields(%{type: "event"} = assigns) do
    ~H"""
    <.input field={@form[:event]} type="select" options={enum_options(VersionEvent.Event)}>
      <:label>Boundary</:label>
    </.input>
    <.input
      field={@form[:commit_sha]}
      type="text"
      placeholder="40-char commit SHA"
      class="w-full input font-mono"
    >
      <:label>Commit SHA (preferred)</:label>
    </.input>
    <.input field={@form[:version]} type="text" placeholder={~s(e.g. "0", "1.4.2" or "2026-01-19")}>
      <:label>Explicit version (when no commit applies)</:label>
    </.input>
    <.input field={@form[:note]} type="text">
      <:label>Note (which release branch, why)</:label>
    </.input>
    """
  end

  defp child_fields(%{type: "reference"} = assigns) do
    ~H"""
    <.input field={@form[:url]} type="text" class="w-full input font-mono">
      <:label>URL</:label>
    </.input>
    <.input
      field={@form[:tags]}
      type="text"
      value={list_value(@form[:tags])}
      placeholder="vendor-advisory, patch"
    >
      <:label>Tags (comma separated)</:label>
    </.input>
    <.input field={@form[:position]} type="number">
      <:label>Position (advisory first)</:label>
    </.input>
    """
  end

  defp child_fields(%{type: "credit"} = assigns) do
    ~H"""
    <.input field={@form[:name]} type="text">
      <:label>Name</:label>
    </.input>
    <.input field={@form[:organization]} type="text">
      <:label>Organization (optional)</:label>
    </.input>
    <.input field={@form[:credit_type]} type="select" options={enum_options(CaseCredit.CreditType)}>
      <:label>Credit type</:label>
    </.input>
    <.input field={@form[:position]} type="number">
      <:label>Position</:label>
    </.input>
    """
  end

  defp child_fields(%{type: "weakness"} = assigns) do
    ~H"""
    <.input field={@form[:cwe_id]} type="number" placeholder="613">
      <:label>CWE number</:label>
    </.input>
    """
  end

  defp child_fields(%{type: "impact"} = assigns) do
    ~H"""
    <.input field={@form[:capec_id]} type="number" placeholder="593">
      <:label>CAPEC number</:label>
    </.input>
    """
  end

  # Renders an {:array, :string} form value back into its comma-separated
  # text-input representation.
  defp list_value(field) do
    case field.value do
      values when is_list(values) -> Enum.join(values, ", ")
      value -> value
    end
  end
end
