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
  only to hide dead buttons. Child rows are added and edited through one modal
  `AshPhoenix.Form` at a time, affected packages included, so every edit in the
  workspace works the same way. Per-row actions stay raw.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.CaseComponents
  import VarselWeb.CaseFormComponents
  import VarselWeb.UserComponents, only: [user_badge: 1, user_name: 1]

  alias Varsel.Accounts
  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case.Calculations.Preview.Diff
  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseImpact
  alias Varsel.Cases.CaseReference
  alias Varsel.Cases.CaseWeakness
  alias Varsel.Cases.ChildParams
  alias Varsel.Cases.Derivation.Display
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.Projection
  alias Varsel.Cases.Proposal.Build
  alias Varsel.Cases.Readiness
  alias Varsel.Cases.VersionEvent
  alias Varsel.CVE
  alias Varsel.Types.CVSS
  alias VarselWeb.AffectedComponents
  alias VarselWeb.CveView

  @case_loads [
    :cve_id,
    :cve_record,
    :affected_summary,
    :derived_references,
    # :avatar_url wherever a user is drawn as an avatar disc.
    assignments: [user: [:avatar_url]],
    references: [],
    credits: [],
    weaknesses: [weakness: [:cwe_id, :name]],
    impacts: [attack_pattern: [:capec_id, :name]],
    proposals: [author: [:avatar_url], resolved_by: []],
    affected_packages: [:derivation_state, channels: [:purl], version_events: []],
    comments: [:author],
    vulnerability_reports: [reporter: [:avatar_url]]
  ]

  # Modal child-form registry: UI type -> resource + labels. Every resource
  # has an :add create action (overridable via `create_action` for the
  # well-known-product presets); those with `edit?` also have an :edit update.
  @children %{
    "package" => %{
      resource: AffectedPackage,
      title: "affected package",
      edit?: true,
      target: :affected_package
    },
    "package_otp" => %{
      resource: AffectedPackage,
      create_action: :add_otp,
      preset: :otp,
      title: "Erlang/OTP package",
      edit?: false,
      target: :affected_package
    },
    "package_elixir" => %{
      resource: AffectedPackage,
      create_action: :add_elixir,
      preset: :elixir,
      title: "Elixir package",
      edit?: false,
      target: :affected_package
    },
    "package_gleam" => %{
      resource: AffectedPackage,
      create_action: :add_gleam,
      preset: :gleam,
      title: "Gleam package",
      edit?: false,
      target: :affected_package
    },
    "channel" => %{
      resource: PackageChannel,
      title: "distribution channel",
      edit?: true,
      target: :package_channel
    },
    "event" => %{
      resource: VersionEvent,
      title: "version boundary",
      edit?: true,
      target: :version_event
    },
    "reference" => %{resource: CaseReference, title: "reference", edit?: true, target: :reference},
    "credit" => %{resource: CaseCredit, title: "credit", edit?: true, target: :credit},
    "weakness" => %{
      resource: CaseWeakness,
      title: "CWE classification",
      edit?: false,
      target: :weakness
    },
    "impact" => %{
      resource: CaseImpact,
      title: "CAPEC classification",
      edit?: false,
      target: :impact
    }
  }

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    socket =
      socket
      |> assign(
        case_id: id,
        # /edit and /propose act as deep links into the one workspace:
        # summary open for editing, suggest preset accordingly.
        suggest?: socket.assigns.live_action == :propose,
        editing_section: if(socket.assigns.live_action == :view, do: nil, else: "summary"),
        mode: :view,
        refreshing: false,
        child_form: nil,
        cve_picker: nil,
        preview: nil,
        validation: nil,
        preview_open?: false,
        preview_tab: "validation",
        diff: nil,
        users: nil,
        catalog_options: nil,
        expanded_payloads: MapSet.new()
      )
      |> keep_live(:case_record, &load_case/1,
        subscribe: ["case:#{id}", "case_proposal:#{id}", "case_comment:#{id}"],
        after_fetch: &after_case_fetch/2
      )

    {:ok, socket}
  end

  defp load_case(socket) do
    case Cases.get_case(socket.assigns.case_id,
           actor: socket.assigns.current_user,
           load: @case_loads
         ) do
      {:ok, case_record} -> case_record
      {:error, _error} -> nil
    end
  end

  # nil: the case vanished or became inaccessible (on mount and refetch alike).
  defp after_case_fetch(nil, socket) do
    socket |> put_flash(:error, "Case not found.") |> push_navigate(to: ~p"/cases")
  end

  defp after_case_fetch(case_record, socket), do: assign_case(socket, case_record)

  @impl Phoenix.LiveView
  def handle_params(_params, _uri, socket) do
    {:noreply, assign_case(socket, socket.assigns.case_record)}
  end

  ## ------------------------------------------------------------ case content

  @impl Phoenix.LiveView
  def handle_event("toggle_suggest", _params, socket) do
    socket = assign(socket, suggest?: not socket.assigns.suggest?)
    {:noreply, assign_case(socket, socket.assigns.case_record)}
  end

  def handle_event("toggle_payload", %{"report_id" => report_id}, socket) do
    expanded = socket.assigns.expanded_payloads

    expanded =
      if MapSet.member?(expanded, report_id) do
        MapSet.delete(expanded, report_id)
      else
        MapSet.put(expanded, report_id)
      end

    {:noreply, assign(socket, expanded_payloads: expanded)}
  end

  def handle_event("edit_section", %{"section" => section}, socket) when section in ["summary", "severity"] do
    socket = assign(socket, editing_section: section)
    {:noreply, assign_case(socket, socket.assigns.case_record)}
  end

  def handle_event("cancel_edit", _params, socket) do
    socket = assign(socket, editing_section: nil)
    {:noreply, assign_case(socket, socket.assigns.case_record)}
  end

  def handle_event("validate", %{"form" => params}, socket) do
    {:noreply, assign(socket, content_form: AshPhoenix.Form.validate(socket.assigns.content_form, params))}
  end

  # Edit mode saves directly; propose mode diffs against the projection (the
  # case with all open proposals applied) and creates proposals from the
  # changes — untouched proposed values create nothing, changed ones become
  # counter-proposals.
  def handle_event("save", %{"form" => params} = raw, socket) do
    case put_override(params, raw) do
      {:ok, params} ->
        case socket.assigns.mode do
          :propose ->
            {:noreply, propose_content_changes(socket, params, presence(raw["reasoning"]))}

          _edit ->
            save_content(socket, params)
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
          put_flash(socket, :info, "Case #{humanize_action(action)}.")

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  # Opening the picker reads the pool fresh: the ID list is the one thing on
  # this page that another POC can invalidate between page load and click.
  def handle_event("assign_cve_id", _params, socket) do
    actor = socket.assigns.current_user

    {:noreply, assign(socket, cve_picker: CVE.list_assignable_cve_records!(actor: actor))}
  end

  def handle_event("cancel_cve_picker", _params, socket) do
    {:noreply, assign(socket, :cve_picker, nil)}
  end

  # Both paths land here: "next free ID" sends no cve_record_id and lets the
  # action pick, a chosen row sends the one it names.
  def handle_event("confirm_assign_cve_id", params, socket) do
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
        {:ok, _case_record} -> put_flash(socket, :info, "Case closed.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_event("refresh_derivation", _params, socket) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    {:noreply,
     socket
     |> assign(preview: :loading, refreshing: true)
     |> start_async(:preview, fn ->
       {:ok, _} = Cases.refresh_case_derivation(case_record, actor: actor)
       Cases.get_case!(case_record.id, load: [:preview, :validation], actor: actor)
     end)}
  end

  def handle_event("preview", _params, socket) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    socket =
      if socket.assigns.preview_open? do
        socket
      else
        assign(socket, preview_tab: "validation", diff: nil)
      end

    {:noreply,
     socket
     |> assign(preview: :loading, preview_open?: true)
     |> start_async(:preview, fn ->
       Cases.get_case!(case_record.id, load: [:preview, :validation], actor: actor)
     end)}
  end

  def handle_event("close_preview", _params, socket) do
    {:noreply, assign(socket, preview_open?: false, preview: nil, validation: nil, diff: nil)}
  end

  def handle_event("preview_tab", %{"tab" => tab}, socket) when tab in ["validation", "json", "diff"] do
    socket = assign(socket, preview_tab: tab)

    # The diff (against the record published at MITRE) is computed lazily the
    # first time its tab opens.
    socket =
      if tab == "diff" and is_nil(socket.assigns.diff) do
        start_diff(socket)
      else
        socket
      end

    {:noreply, socket}
  end

  ## -------------------------------------------------------------- child rows

  def handle_event("new_child", %{"type" => type} = params, socket) do
    %{resource: resource, title: title} = config = Map.fetch!(@children, type)

    form =
      resource
      |> AshPhoenix.Form.for_create(Map.get(config, :create_action, :add),
        as: "child",
        actor: socket.assigns.current_user
      )
      |> to_form()

    parent =
      params
      |> Map.take(["affected_package_id"])
      |> Map.put("case_id", socket.assigns.case_record.id)
      |> put_append_position(type, socket.assigns.display_case)

    {:noreply,
     socket
     |> ensure_catalog_options(type)
     |> assign(
       child_form: %{
         form: form,
         type: type,
         title: modal_title("Add", title, socket),
         parent: parent,
         channel_options: channel_options(type, params, socket)
       }
     )}
  end

  # In propose mode the modal edits the *projected* row (open proposals
  # applied), so untouched proposed values don't re-propose.
  def handle_event("edit_child", %{"type" => type, "id" => id}, socket) do
    %{resource: resource, title: title} = Map.fetch!(@children, type)

    row =
      case socket.assigns.mode do
        :propose -> find_projected_row(socket.assigns.display_case, type, id)
        _edit -> Ash.get!(resource, id, actor: socket.assigns.current_user)
      end

    form =
      row
      |> AshPhoenix.Form.for_update(:edit, as: "child", actor: socket.assigns.current_user)
      |> to_form()

    {:noreply,
     assign(socket,
       child_form: %{
         form: form,
         type: type,
         title: modal_title("Edit", title, socket),
         parent: %{},
         channel_options: []
       }
     )}
  end

  def handle_event("validate_child", %{"child" => params}, socket) do
    %{form: form, type: type} = socket.assigns.child_form
    params = ChildParams.normalize(type, params, socket.assigns.child_form.parent)
    form = AshPhoenix.Form.validate(form, params)

    {:noreply, assign(socket, child_form: %{socket.assigns.child_form | form: form})}
  end

  def handle_event("submit_child", %{"child" => params} = raw, socket) do
    %{form: form, type: type} = socket.assigns.child_form
    params = ChildParams.normalize(type, params, socket.assigns.child_form.parent)

    case socket.assigns.mode do
      :propose ->
        {:noreply, propose_child_changes(socket, params, presence(raw["reasoning"]))}

      _edit ->
        case AshPhoenix.Form.submit(form, params: params) do
          {:ok, _row} ->
            {:noreply, socket |> assign(child_form: nil) |> put_flash(:info, "Saved.")}

          {:error, form} ->
            {:noreply, assign(socket, child_form: %{socket.assigns.child_form | form: form})}
        end
    end
  end

  def handle_event("cancel_child", _params, socket) do
    {:noreply, assign(socket, child_form: nil)}
  end

  # The package modal's nested program-file rows.
  def handle_event("add_program_file", _params, socket) do
    {:noreply, update_child_form(socket, &AshPhoenix.Form.add_form(&1, :program_files))}
  end

  def handle_event("remove_program_file", %{"path" => path}, socket) do
    {:noreply, update_child_form(socket, &AshPhoenix.Form.remove_form(&1, path))}
  end

  # Edit mode destroys the row; propose mode files a :delete proposal.
  def handle_event("remove_child", %{"type" => type, "id" => id}, socket) do
    %{resource: resource, target: target} = Map.fetch!(@children, type)
    actor = socket.assigns.current_user

    socket =
      case socket.assigns.mode do
        :propose ->
          create_proposals(socket, [
            %{
              case_id: socket.assigns.case_record.id,
              target: target,
              operation: :delete,
              target_id: id
            }
          ])

        _edit ->
          with {:ok, row} <- Ash.get(resource, id, actor: actor),
               :ok <- Ash.destroy(row, action: :remove, actor: actor) do
            put_flash(socket, :info, "Removed.")
          else
            {:error, error} -> put_flash(socket, :error, errors_to_string(error))
          end
      end

    {:noreply, socket}
  end

  # Pushed by the .DragSort hook with the row ids in their new DOM order.
  def handle_event("reorder_references", %{"ids" => ids}, socket) do
    reorder_rows(socket, socket.assigns.case_record.references, &Cases.edit_case_reference/3, ids)
  end

  def handle_event("reorder_credits", %{"ids" => ids}, socket) do
    reorder_rows(socket, socket.assigns.case_record.credits, &Cases.edit_case_credit/3, ids)
  end

  ## ------------------------------------------------------------- assignments

  def handle_event("assign_user", %{"user_id" => user_id}, socket) do
    socket =
      case Cases.assign_case_user(
             %{case_id: socket.assigns.case_record.id, user_id: user_id},
             actor: socket.assigns.current_user
           ) do
        {:ok, _assignment} -> put_flash(socket, :info, "User assigned.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_event("unassign_user", %{"id" => id}, socket) do
    assignment = Enum.find(socket.assigns.case_record.assignments, &(&1.id == id))

    socket =
      case Cases.unassign_case_user(assignment, actor: socket.assigns.current_user) do
        :ok -> put_flash(socket, :info, "User unassigned.")
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

  # The button is only offered for a section whose suggestions cannot supersede
  # one another, but the pool is shared: another reviewer may resolve one
  # between the render and the click. So each is accepted on its own and the
  # flash says what actually happened rather than assuming all of them landed.
  def handle_event("accept_section_proposals", %{"section" => section_id}, socket) do
    actor = socket.assigns.current_user

    {accepted, failed} =
      socket.assigns.case_record
      |> section_suggestions(section_id)
      |> Enum.split_with(fn proposal ->
        match?({:ok, _proposal}, Cases.accept_case_proposal(proposal, %{}, actor: actor))
      end)

    {:noreply, put_flash_for_bulk_accept(socket, length(accepted), length(failed))}
  end

  def handle_event("withdraw_proposal", %{"id" => id}, socket) do
    proposal = Enum.find(socket.assigns.case_record.proposals, &(&1.id == id))

    socket =
      case Cases.withdraw_case_proposal(proposal, actor: socket.assigns.current_user) do
        {:ok, _proposal} -> put_flash(socket, :info, "Proposal withdrawn.")
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
        {:ok, _comment} -> socket
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  @impl Phoenix.LiveView
  def handle_async(:preview, {:ok, case_record}, socket) do
    {:noreply,
     assign(socket,
       preview: case_record.preview,
       validation: case_record.validation,
       refreshing: false
     )}
  end

  def handle_async(:preview, {:exit, reason}, socket) do
    {:noreply,
     socket
     |> assign(preview: nil, validation: nil, refreshing: false)
     |> put_flash(:error, "Preview failed: #{Exception.format_exit(reason)}")}
  end

  def handle_async(:publish, {:ok, result}, socket) do
    socket =
      case result do
        {:ok, _case_record} ->
          put_flash(socket, :info, "Publish handed to MITRE.")

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_async(:publish, {:exit, reason}, socket) do
    {:noreply, put_flash(socket, :error, "Publish failed: #{Exception.format_exit(reason)}")}
  end

  def handle_async(:diff, {:ok, lines}, socket) do
    {:noreply, assign(socket, diff: lines)}
  end

  def handle_async(:diff, {:exit, reason}, socket) do
    {:noreply,
     socket
     |> assign(diff: nil)
     |> put_flash(:error, "Diff failed: #{Exception.format_exit(reason)}")}
  end

  ## ----------------------------------------------------------------- helpers

  # Only the summary editor carries the CNA-override textarea; the severity
  # editor's partial save must not touch (and thereby clear) the override.
  defp put_override(params, %{"cna_override_json" => json}) do
    case decode_override(json) do
      {:ok, override} -> {:ok, Map.put(params, "cna_override", override)}
      :error -> :error
    end
  end

  defp put_override(params, _raw), do: {:ok, params}

  defp start_diff(socket) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    socket
    |> assign(diff: :loading)
    |> start_async(:diff, fn ->
      # Both sides come from calculations loaded under the actor, so the diff is
      # as authorized as the page load.
      case_record =
        Cases.get_case!(case_record.id, load: [:preview, :published_cna], actor: actor)

      Diff.lines(
        case_record.published_cna || %{},
        get_in(case_record.preview.cve_record, ["containers", "cna"])
      )
    end)
  end

  defp save_content(socket, params) do
    case AshPhoenix.Form.submit(socket.assigns.content_form, params: params) do
      {:ok, _case_record} ->
        {:noreply,
         socket
         |> assign(editing_section: nil, content_form: nil)
         |> put_flash(:info, "Case saved.")}

      {:error, form} ->
        {:noreply, assign(socket, content_form: form)}
    end
  end

  defp put_flash_for_bulk_accept(socket, 0, _failed) do
    put_flash(
      socket,
      :error,
      "Nothing was accepted — the suggestions have already been resolved."
    )
  end

  defp put_flash_for_bulk_accept(socket, accepted, 0) do
    put_flash(socket, :info, "Accepted #{suggestion_count(accepted)}.")
  end

  defp put_flash_for_bulk_accept(socket, accepted, failed) do
    put_flash(
      socket,
      :info,
      "Accepted #{suggestion_count(accepted)}; #{failed} could not be and stayed open."
    )
  end

  defp suggestion_count(1), do: "1 suggestion"
  defp suggestion_count(count), do: "#{count} suggestions"

  defp resolve_proposal(socket, id, note, fun, verb) do
    proposal = Enum.find(socket.assigns.case_record.proposals, &(&1.id == id))
    args = %{resolution_note: presence(note)}

    socket =
      case fun.(proposal, args, actor: socket.assigns.current_user) do
        {:ok, _proposal} -> put_flash(socket, :info, "Proposal #{verb}.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  defp assign_case(socket, case_record) do
    actor = socket.assigns.current_user
    mode = derive_mode(case_record, actor, socket.assigns.suggest?)

    # Propose mode works against the projection: the case with every open
    # proposal applied as if accepted.
    projection = if mode == :propose, do: Projection.project(case_record)
    display_case = if projection, do: projection.case, else: case_record

    content_form =
      if mode in [:edit, :propose] and socket.assigns.editing_section in ["summary", "severity"] do
        display_case
        |> AshPhoenix.Form.for_update(:edit, as: "form", actor: actor)
        |> to_form()
      end

    users = if Accounts.can_list_users?(actor), do: Accounts.list_users!(actor: actor), else: []

    assign(socket,
      case_record: case_record,
      display_case: display_case,
      projection: projection,
      mode: mode,
      content_form: content_form,
      can_comment: can_comment?(case_record, actor),
      can_refresh: Cases.can_refresh_case_derivation?(actor, case_record, validate?: true),
      users: users,
      page_title: case_record.title || "Case"
    )
  end

  # Intent is a property of the save, not the page: who you are and the case
  # state decide whether edits apply directly or become suggestions. The
  # suggest toggle only matters while direct editing is possible; on frozen
  # cases suggesting is all there is.
  defp derive_mode(case_record, actor, suggest?) do
    cond do
      can_edit?(case_record, actor) and not suggest? -> :edit
      can_propose?(case_record, actor) -> :propose
      can_edit?(case_record, actor) -> :edit
      true -> :view
    end
  end

  defp suggest_forced?(case_record, actor) do
    not can_edit?(case_record, actor) and can_propose?(case_record, actor)
  end

  ## ------------------------------------------------------ proposal building

  # Content saved in propose mode: `Build` diffs the params against the
  # projection; this only supplies the assigns it needs and files the result.
  defp propose_content_changes(socket, params, reasoning) do
    %{display_case: display_case, projection: projection, case_record: case_record} =
      socket.assigns

    proposals =
      Build.content_proposals(case_record.id, display_case, projection, params, reasoning)

    create_proposals(socket, proposals)
  end

  # "Propose" in the child modal: an :insert proposal for an add form, one
  # :set proposal per changed field for an edit form.
  defp propose_child_changes(socket, params, reasoning) do
    %{form: form, type: type} = socket.assigns.child_form
    config = Map.fetch!(@children, type)
    case_id = socket.assigns.case_record.id

    # Leaving the form machinery: nested program-file rows become the stored
    # list shape, both for payloads and for the changed-field diff below.
    params =
      case params do
        %{"program_files" => %{} = files} ->
          Map.put(params, "program_files", ChildParams.program_files_list(files))

        params ->
          params
      end

    proposals =
      case form.source.type do
        :create ->
          Build.insert_proposals(config, case_id, params, reasoning)

        :update ->
          Build.set_proposals(
            config,
            case_id,
            form.source.data,
            socket.assigns.projection,
            params,
            reasoning
          )
      end

    socket = assign(socket, child_form: nil)
    create_proposals(socket, proposals)
  end

  defp create_proposals(socket, []), do: put_flash(socket, :info, "No changes to propose.")

  defp create_proposals(socket, proposals) do
    actor = socket.assigns.current_user

    result =
      Enum.reduce_while(proposals, 0, fn attrs, count ->
        case Cases.create_case_proposal(attrs, actor: actor) do
          {:ok, _proposal} -> {:cont, count + 1}
          {:error, error} -> {:halt, {:error, error, count}}
        end
      end)

    case result do
      {:error, error, count} ->
        put_flash(
          socket,
          :error,
          "Created #{count} proposal(s), then failed: #{errors_to_string(error)}"
        )

      count ->
        put_flash(socket, :info, "Created #{count} proposal(s).")
    end
  end

  defp decode_override(nil), do: {:ok, nil}

  defp decode_override(json) do
    case String.trim(json) do
      "" ->
        {:ok, nil}

      trimmed ->
        case JSON.decode(trimmed) do
          {:ok, override} when is_map(override) -> {:ok, override}
          _other -> :error
        end
    end
  end

  defp presence(nil), do: nil

  defp presence(value) when is_binary(value), do: if(String.trim(value) == "", do: nil, else: value)

  # An amendment: the backing CVE record already carries a published CNA
  # container, so publishing pushes an update — a diff against it is meaningful.
  defp amendment?(case_record) do
    match?(
      %{cve_record: %{cve_json: %{"containers" => %{"cna" => %{}}}}},
      case_record
    )
  end

  defp can_edit?(case_record, user), do: Cases.can_edit_case?(user, case_record, %{}, validate?: true)

  # Writing on a case asks two separate questions, and only the first is about
  # the row being written. Whether this is your case to work on is what reading
  # it already answers — POC, or assigned — and asking the child action instead
  # would not work: its policy reaches the case through a row that does not
  # exist yet, so the check comes back `:unknown` until the insert runs.
  defp can_comment?(case_record, user), do: Ash.can?({case_record, :read}, user)

  # Whether the case is still open to proposals is the second question. Asking
  # the action would mean inventing a whole proposal to ask about, since its
  # target validation runs first and rejects a shapeless one — so the state
  # itself is read, mirroring `Proposal.Validations.CaseState`.
  defp can_propose?(case_record, user), do: can_comment?(case_record, user) and case_record.state != :closed

  defp marks(nil), do: %{phantom: MapSet.new(), deleted: MapSet.new()}
  defp marks(projection), do: %{phantom: projection.phantom_ids, deleted: projection.deleted_ids}

  @doc "DaisyUI badge class for a case state."
  def state_badge_class(:draft), do: "badge-warning"
  def state_badge_class(:review), do: "badge-info"
  def state_badge_class(:approved), do: "badge-accent"
  def state_badge_class(:publishing), do: "badge-info"
  def state_badge_class(:published), do: "badge-success"
  def state_badge_class(:closed), do: "badge-neutral"
  def state_badge_class(_other), do: "badge-ghost"

  # The +/- prefixes make the joined text valid diff syntax, so the
  # code_block's Lumis "diff" grammar colors the lines.
  defp diff_line_text({:del, line}), do: "- " <> line
  defp diff_line_text({:ins, line}), do: "+ " <> line
  defp diff_line_text({:eq, line}), do: "  " <> line
  defp diff_line_text({:skip, count}), do: "  ⋯ #{count} unchanged lines"

  defp humanize_action(action), do: String.replace(action, "_", " ")

  defp pretty_json(nil), do: ""
  # Jason, not the stdlib JSON module: only Jason has a pretty printer.
  defp pretty_json(value), do: Jason.encode!(value, pretty: true)

  defp enum_options(enum), do: Enum.map(enum.values(), &{&1 |> to_string() |> String.replace("_", " "), &1})

  # The value a :set suggestion would replace, read from the raw (unprojected)
  # case so the diff shows what acceptance actually changes. Only open
  # proposals diff against the live case — once resolved, the current value
  # no longer reflects what the suggestion was made against.
  defp proposal_old_value(case_record, %{operation: :set, state: :open} = proposal) do
    target = proposal_target_row(case_record, proposal)
    field = String.to_existing_atom(proposal.field_name)
    if target, do: Map.get(target, field)
  rescue
    ArgumentError -> nil
  end

  defp proposal_old_value(_case_record, _proposal), do: nil

  defp proposal_target_row(case_record, %{target: :case}), do: case_record

  defp proposal_target_row(case_record, proposal) do
    rows =
      case proposal.target do
        :affected_package -> case_record.affected_packages
        :package_channel -> Enum.flat_map(case_record.affected_packages, & &1.channels)
        :version_event -> Enum.flat_map(case_record.affected_packages, & &1.version_events)
        :reference -> case_record.references
        :credit -> case_record.credits
        :weakness -> case_record.weaknesses
        :impact -> case_record.impacts
      end

    Enum.find(rows, &(&1.id == proposal.target_id))
  end

  defp format_proposal_value(nil), do: nil
  defp format_proposal_value(value) when is_binary(value), do: value
  defp format_proposal_value(%CVSS{vector: vector}), do: vector

  defp format_proposal_value(value) when is_list(value) do
    Enum.map_join(value, "\n", &format_proposal_value/1)
  end

  defp format_proposal_value(value) when is_atom(value), do: to_string(value)

  defp format_proposal_value(%_{} = struct) do
    struct |> Map.from_struct() |> Map.delete(:__meta__) |> pretty_json()
  end

  defp format_proposal_value(value), do: pretty_json(value)

  ## ------------------------------------------------------------------ render

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_user={@current_user} current_path={@current_path}>
      <div class={@preview_open? && "opacity-45"}>
        <.page_header>
          <:eyebrow>
            Case <span :if={@case_record.cve_id} class="font-mono">· {@case_record.cve_id}</span>
            <.copy_button
              :if={@case_record.cve_id}
              value={@case_record.cve_id}
              label={"Copy #{@case_record.cve_id}"}
              class="align-text-bottom"
            />
            <span :if={is_nil(@case_record.cve_id)} class="opacity-60">· no CVE ID assigned</span>
            <span class="text-base-content/50">
              · draft opened {Calendar.strftime(@case_record.inserted_at, "%b %-d, %Y")}
            </span>
          </:eyebrow>
          <:title>{@case_record.title || "Untitled case"}</:title>
          <:meta><.lifecycle_stepper state={@case_record.state} /></:meta>
          <:actions>
            <button
              :if={@mode != :view and can_propose?(@case_record, @current_user)}
              phx-click="toggle_suggest"
              disabled={suggest_forced?(@case_record, @current_user)}
              title={
                if suggest_forced?(@case_record, @current_user),
                  do: "The case is frozen — edits become suggestions",
                  else: "Route your edits through suggestions instead of applying them"
              }
              class={[
                "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-bold",
                if(@mode == :propose,
                  do: "border-info bg-info/15 text-info",
                  else: "border-info/40 text-info"
                )
              ]}
            >
              ✎ Suggest: {if @mode == :propose, do: "on", else: "off"}
            </button>
            <button class="btn btn-sm btn-eef-quiet" phx-click="preview">Preview</button>
            <.lifecycle_buttons
              case_record={@case_record}
              current_user={@current_user}
              include_publish={false}
              publish_blocked={false}
            />
          </:actions>
        </.page_header>

        <.page_container width={:wide}>
          <:left width={:narrow} class="lg:sticky lg:top-24">
            <.section_nav sections={workspace_sections(@display_case, @case_record.proposals)} />
          </:left>

          <div class="space-y-8 min-w-0">
            <div id="summary">
              <.content_section
                case_record={@display_case}
                raw_case_record={@case_record}
                content_form={@editing_section == "summary" && @content_form}
                mode={@mode}
                current_user={@current_user}
                can_resolve={can_edit?(@case_record, @current_user)}
              />
            </div>
            <div id="severity">
              <.severity_section
                case_record={@display_case}
                raw_case_record={@case_record}
                form={@editing_section == "severity" && @content_form}
                mode={@mode}
                current_user={@current_user}
                can_resolve={can_edit?(@case_record, @current_user)}
              />
            </div>
            <div id="affected">
              <.affected_section
                case_record={@display_case}
                raw_case_record={@case_record}
                mode={@mode}
                marks={marks(@projection)}
                current_user={@current_user}
                can_resolve={can_edit?(@case_record, @current_user)}
                can_refresh={@can_refresh}
                refreshing={@refreshing}
              />
            </div>
            <.rows_section
              id="references"
              heading="References"
              type="reference"
              add_label="Add reference"
              rows={@display_case.references}
              mode={@mode}
              marks={marks(@projection)}
              sort_event="reorder_references"
              raw_case_record={@case_record}
              current_user={@current_user}
              can_resolve={can_edit?(@case_record, @current_user)}
              has_footer?={@display_case.derived_references != []}
            >
              <:row :let={reference}>
                <span class="flex min-w-0 items-center gap-2 text-sm">
                  <CveView.reference url={reference.url} tags={reference.tags} pills={:all} />
                </span>
              </:row>
              <:footer>
                <.derived_references refs={@display_case.derived_references} />
              </:footer>
            </.rows_section>
            <.rows_section
              id="credits"
              heading="Credits"
              type="credit"
              add_label="Add credit"
              rows={@display_case.credits}
              mode={@mode}
              marks={marks(@projection)}
              sort_event="reorder_credits"
              raw_case_record={@case_record}
              current_user={@current_user}
              can_resolve={can_edit?(@case_record, @current_user)}
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
              rows={@display_case.weaknesses}
              mode={@mode}
              marks={marks(@projection)}
              raw_case_record={@case_record}
              current_user={@current_user}
              can_resolve={can_edit?(@case_record, @current_user)}
            >
              <:row :let={weakness}>
                <.link
                  href={"https://cwe.mitre.org/data/definitions/#{weakness.cwe_id}.html"}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="link font-mono"
                >
                  CWE-{weakness.cwe_id}
                </.link>
                {weakness.weakness.name}
              </:row>
            </.rows_section>
            <.rows_section
              id="impacts"
              heading="Impacts (CAPEC)"
              type="impact"
              add_label="Add CAPEC"
              rows={@display_case.impacts}
              mode={@mode}
              marks={marks(@projection)}
              raw_case_record={@case_record}
              current_user={@current_user}
              can_resolve={can_edit?(@case_record, @current_user)}
            >
              <:row :let={impact}>
                <.link
                  href={"https://capec.mitre.org/data/definitions/#{impact.capec_id}.html"}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="link font-mono"
                >
                  CAPEC-{impact.capec_id}
                </.link>
                {impact.attack_pattern.name}
              </:row>
            </.rows_section>

            <.resolved_suggestions_disclosure
              :if={resolved_proposals(@case_record) != []}
              case_record={@case_record}
              current_user={@current_user}
              can_resolve={can_edit?(@case_record, @current_user)}
            />
          </div>

          <:right width={:wide} class="space-y-4">
            <.panel id="suggestions">
              <:title>Suggestions</:title>
              <ul :if={open_proposals(@case_record) != []} class="space-y-1.5 text-sm">
                <li :for={proposal <- open_proposals(@case_record)} class="flex items-center gap-2">
                  <span class="text-info font-bold shrink-0">◆</span>
                  <span class="truncate text-base-content/80">
                    {proposal_field_ref(proposal)}
                    <span class="text-base-content/50">— <.user_name user={proposal.author} /></span>
                  </span>
                  <.link
                    href={"#suggestion-#{proposal.id}"}
                    class="link link-hover text-primary text-xs ml-auto shrink-0"
                  >
                    Jump
                  </.link>
                </li>
              </ul>
              <p :if={open_proposals(@case_record) == []} class="text-sm text-base-content/60">
                No open suggestions.
              </p>
            </.panel>
            <.panel>
              <:title>Activity</:title>
              <form :if={@can_comment} phx-submit="post_comment" class="mb-4">
                <textarea
                  name="body"
                  rows="2"
                  required
                  placeholder="Write a comment…"
                  class="w-full textarea text-sm"
                ></textarea>
                <button type="submit" class="btn btn-outline btn-xs mt-1">Comment</button>
              </form>
              <.activity_feed entries={activity_entries(@case_record)} />
            </.panel>
            <.assignments_section
              :if={Cases.can_assign_case_user?(@current_user, %{case_id: @case_record.id})}
              case_record={@case_record}
              users={@users}
              current_user={@current_user}
            />
            <.reports_section
              :if={@case_record.vulnerability_reports != []}
              case_record={@case_record}
              triage?={CVE.can_list_vulnerability_reports?(@current_user)}
              expanded_payloads={@expanded_payloads}
            />
            <.close_link
              :if={Cases.can_close_case?(@current_user, @case_record, validate?: true)}
              case_record={@case_record}
            />
          </:right>

          <.child_modal
            :if={@child_form}
            child_form={@child_form}
            catalog_options={@catalog_options}
            mode={@mode}
          />
        </.page_container>
      </div>

      <.preview_overlay
        :if={@preview_open?}
        case_record={@case_record}
        current_user={@current_user}
        preview={@preview}
        validation={@validation}
        preview_tab={@preview_tab}
        diff={@diff}
        amendment={amendment?(@case_record)}
      />

      <.cve_picker_modal :if={@cve_picker} records={@cve_picker} />
    </Layouts.app>
    """
  end

  # The rail's per-section markers: readiness (heuristic) plus open-suggestion
  # counts mapped onto the section a proposal targets.
  defp workspace_sections(display_case, proposals) do
    open = Enum.filter(proposals, &(&1.state == :open))
    counts = Enum.frequencies_by(open, &section_for_proposal/1)

    sections =
      display_case
      |> Readiness.sections()
      |> Enum.map(&Map.put(&1, :suggestions, Map.get(counts, &1.id, 0)))

    sections ++
      [%{id: "suggestions", label: "Suggestions", status: nil, suggestions: length(open)}]
  end

  defp section_for_proposal(%{target: target}) when target in [:affected_package, :package_channel, :version_event],
    do: "affected"

  defp section_for_proposal(%{target: :case, field_name: "cvss_v4"}), do: "severity"
  defp section_for_proposal(%{target: :reference}), do: "references"
  defp section_for_proposal(%{target: :credit}), do: "credits"
  defp section_for_proposal(%{target: :weakness}), do: "weaknesses"
  defp section_for_proposal(%{target: :impact}), do: "impacts"
  defp section_for_proposal(_case_field), do: "summary"

  defp open_proposals(case_record) do
    Enum.filter(case_record.proposals, &(&1.state == :open))
  end

  # Open suggestions targeting one workspace section, oldest first — rendered
  # inline inside that section's own card rather than a separate aggregate.
  defp section_suggestions(case_record, section_id) do
    case_record
    |> open_proposals()
    |> Enum.filter(&(section_for_proposal(&1) == section_id))
    |> Enum.sort_by(& &1.inserted_at, DateTime)
  end

  defp comments_by_proposal(case_record) do
    Enum.group_by(case_record.comments, & &1.proposal_id)
  end

  defp resolved_proposals(case_record) do
    case_record.proposals
    |> Enum.reject(&(&1.state == :open))
    |> Enum.sort_by(& &1.resolved_at, {:desc, DateTime})
  end

  # Comments and suggestion events interleaved, newest first.
  defp activity_entries(case_record) do
    comments =
      Enum.map(case_record.comments, fn comment ->
        %{
          kind: :comment,
          who: comment.author,
          at: comment.inserted_at,
          body: comment.body,
          markdown?: true
        }
      end)

    proposals =
      Enum.map(case_record.proposals, fn proposal ->
        %{
          kind: :proposal,
          who: proposal.author,
          at: proposal.inserted_at,
          body: "suggested a change to",
          chip: proposal_field_ref(proposal),
          suffix: if(proposal.state != :open, do: " (#{proposal.state})")
        }
      end)

    (comments ++ proposals)
    |> Enum.sort_by(& &1.at, {:desc, DateTime})
    |> Enum.take(25)
  end

  defp proposal_field_ref(%{operation: :set, target: :case, field_name: field}), do: "case.#{field}"

  defp proposal_field_ref(%{operation: :set, target: target, field_name: field}), do: "#{target}.#{field}"

  defp proposal_field_ref(%{target: target}), do: to_string(target)

  # Publish lives in the preview slide-over only (`include_publish`), where it
  # is gated visually while render blockers exist.
  defp lifecycle_buttons(assigns) do
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
        :if={
          @include_publish and Cases.can_publish_case?(@current_user, @case_record, validate?: true)
        }
        class={["btn btn-sm btn-eef", @publish_blocked && "opacity-45"]}
        disabled={@publish_blocked}
        phx-click="lifecycle"
        phx-value-action="publish"
        data-confirm="Publish this case to MITRE?"
      >
        Publish to MITRE
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

  # Renders every open suggestion targeting one section, inline inside that
  # section's own card (for Affected: once at section level, below the
  # per-package cards — a package :insert proposal has no card of its own) —
  # the aggregate "Suggestions" section is gone; this is its only rendering
  # now, plus the rail's compact queue and the bottom "Resolved suggestions"
  # disclosure.
  attr :case_record, :map, required: true
  attr :section_id, :string, required: true
  attr :current_user, :map, required: true
  attr :can_resolve, :boolean, required: true

  defp inline_suggestions(assigns) do
    suggestions = section_suggestions(assigns.case_record, assigns.section_id)

    assigns =
      assign(assigns,
        suggestions: suggestions,
        comments: comments_by_proposal(assigns.case_record),
        accept_all_blocker: accept_all_blocker(suggestions)
      )

    ~H"""
    <div
      :if={@can_resolve and length(@suggestions) > 1}
      class="mt-3 flex items-center justify-end gap-2"
    >
      <span :if={@accept_all_blocker} class="text-xs text-base-content/60">
        {@accept_all_blocker}
      </span>
      <button
        class="btn btn-xs btn-primary"
        disabled={@accept_all_blocker != nil}
        phx-click="accept_section_proposals"
        phx-value-section={@section_id}
      >
        Accept all {length(@suggestions)}
      </button>
    </div>

    <div :for={proposal <- @suggestions} class="mt-3">
      <.suggestion_card
        id={"suggestion-#{proposal.id}"}
        proposal={proposal}
        old={format_proposal_value(proposal_old_value(@case_record, proposal))}
        new={format_proposal_value(proposal.proposed_value["value"])}
        can_resolve={@can_resolve}
        own={proposal.author_id == @current_user.id}
        comments={Map.get(@comments, proposal.id, [])}
      >
        <.proposal_payload
          proposal={proposal}
          removing={proposal_target_row(@case_record, proposal)}
          class="mt-1 max-h-96"
        />
      </.suggestion_card>
    </div>
    """
  end

  # Why a section cannot be accepted in one go, or nil when it can.
  #
  # Accepting a proposal supersedes the ones it competes with (see
  # `Varsel.Cases.Proposal.Changes.SupersedeCompeting`), so for those the
  # outcome depends on which is accepted first — a choice a single button
  # cannot make on the reviewer's behalf. The keys below are that change's own:
  # a :delete claims its whole row, two :sets collide on the same field.
  defp accept_all_blocker(proposals) do
    cond do
      Enum.any?(proposals, &(&1.operation == :delete)) ->
        "A removal here would settle the rest — accept them one at a time."

      competing_sets?(proposals) ->
        "Two suggestions change the same field — pick between them first."

      true ->
        nil
    end
  end

  defp competing_sets?(proposals) do
    keys =
      for %{operation: :set} = proposal <- proposals,
          do: {proposal.target, proposal.target_id, proposal.field_name}

    length(Enum.uniq(keys)) < length(keys)
  end

  defp content_section(assigns) do
    ~H"""
    <.edit_mode_notice :if={@content_form} mode={@mode} />
    <.panel editing?={!!@content_form}>
      <:title>{if @content_form, do: "Summary — editing", else: "Summary"}</:title>
      <:actions>
        <button
          :if={@mode != :view and !@content_form}
          class="link link-hover text-primary"
          phx-click="edit_section"
          phx-value-section="summary"
        >
          Edit
        </button>
      </:actions>
      <.form
        :if={@content_form}
        for={@content_form}
        id="case-content-form"
        phx-change="validate"
        phx-submit="save"
      >
        <.input field={@content_form[:title]} type="text">
          <:label>Title</:label>
        </.input>
        <.live_component
          module={VarselWeb.MarkdownInput}
          id="case-description-md"
          field={@content_form[:description_md]}
          label="Description"
          rows={8}
        />
        <.live_component
          module={VarselWeb.MarkdownInput}
          id="case-workarounds-md"
          field={@content_form[:workarounds_md]}
          label="Workarounds (optional)"
          rows={3}
        />
        <.live_component
          module={VarselWeb.MarkdownInput}
          id="case-configurations-md"
          field={@content_form[:configurations_md]}
          label="Configurations (optional)"
          rows={3}
        />
        <.live_component
          module={VarselWeb.MarkdownInput}
          id="case-solutions-md"
          field={@content_form[:solutions_md]}
          label="Solutions (optional)"
          rows={3}
        />
        <.input
          field={@content_form[:discovery]}
          type="select"
          options={enum_options(Varsel.Cases.Case.Discovery)}
        >
          <:label>Discovery</:label>
        </.input>
        <.live_component
          module={VarselWeb.MarkdownInput}
          id="case-internal-notes"
          field={@content_form[:internal_notes]}
          label="Internal notes (never published)"
          rows={3}
        />

        <details class="mt-2">
          <summary class="cursor-pointer text-sm text-base-content/60">
            Advanced: CNA override
          </summary>
          <label class="label mt-2 text-sm">
            RFC 7396 JSON Merge Patch applied to the rendered CNA container
          </label>
          <textarea name="cna_override_json" rows="4" class="w-full textarea font-mono text-sm">{pretty_json(@case_record.cna_override)}</textarea>
        </details>

        <.edit_actions mode={@mode} cancel="cancel_edit" />
      </.form>

      <.case_content
        :if={!@content_form}
        description={@case_record.description_md}
        affected_summary={@case_record.affected_summary}
        configurations={@case_record.configurations_md}
        workarounds={@case_record.workarounds_md}
        solutions={@case_record.solutions_md}
        internal_notes={@case_record.internal_notes}
      />

      <.inline_suggestions
        case_record={@raw_case_record}
        section_id="summary"
        current_user={@current_user}
        can_resolve={@can_resolve}
      />
    </.panel>
    """
  end

  # The editor footer's save button: primary for a direct save, info-colored
  # (with dark text, per the mock) when the same click files a proposal
  # instead — the ONE control the suggest toggle changes about the form.
  # The Severity card: at rest one severity chip (rating + score) beside the
  # truncated CVSS vector; "Open calculator" swaps the body for the CVSS
  # calculator as this card's own editor, with the same save-vs-suggest
  # semantics as the summary editor.
  defp severity_section(assigns) do
    ~H"""
    <.edit_mode_notice :if={@form} mode={@mode} />
    <.panel editing?={!!@form}>
      <:title>{if @form, do: "Severity — editing", else: "Severity"}</:title>
      <:actions>
        <button
          :if={@mode != :view and !@form}
          class="link link-hover text-primary"
          phx-click="edit_section"
          phx-value-section="severity"
        >
          Open calculator
        </button>
      </:actions>

      <.form :if={@form} for={@form} id="case-severity-form" phx-change="validate" phx-submit="save">
        <.live_component
          module={VarselWeb.CvssInput}
          id="case-cvss-v4"
          field={@form[:cvss_v4]}
          label="CVSS v4.0"
        />
        <.edit_actions mode={@mode} cancel="cancel_edit" />
      </.form>

      <div :if={!@form}>
        <div :if={@case_record.cvss_v4} class="flex min-w-0 items-center gap-3">
          <.severity_chip score={@case_record.cvss_v4.score} variant={:full} />
          <span class="min-w-0 truncate font-mono text-xs text-base-content/60">
            {@case_record.cvss_v4.vector}
          </span>
        </div>
        <p :if={is_nil(@case_record.cvss_v4)} class="text-sm text-base-content/60">
          No CVSS score yet.
        </p>
      </div>

      <.inline_suggestions
        case_record={@raw_case_record}
        section_id="severity"
        current_user={@current_user}
        can_resolve={@can_resolve}
      />
    </.panel>
    """
  end

  # One board-A/board-C style card per affected package: package identity in
  # the header, at rest a compact channels table plus a disclosure footer; the
  # package's own "Edit" opens the board-C editor in place (boundary
  # timeline, channel disclosure rows, program files) instead of a modal.
  # Channel and boundary child rows still use the shared `child_modal`.
  defp affected_section(assigns) do
    ~H"""
    <.card_section_header title="Affected" level={:h2}>
      <:actions>
        <div :if={@mode != :view} class="dropdown dropdown-end">
          <div tabindex="0" role="button" class="link link-hover text-primary cursor-pointer text-xs">
            Add package ▾
          </div>
          <ul
            tabindex="0"
            class="dropdown-content menu menu-sm bg-base-100 border border-base-300 rounded-box z-10 w-44 p-1 shadow"
          >
            <li><button phx-click="new_child" phx-value-type="package_otp">Erlang/OTP</button></li>
            <li><button phx-click="new_child" phx-value-type="package_elixir">Elixir</button></li>
            <li><button phx-click="new_child" phx-value-type="package_gleam">Gleam</button></li>
            <li><button phx-click="new_child" phx-value-type="package">Custom package</button></li>
          </ul>
        </div>
      </:actions>
    </.card_section_header>

    <div class="space-y-4">
      <.affected_package_card
        :for={package <- @case_record.affected_packages}
        package={package}
        mode={@mode}
        marks={@marks}
        can_refresh={@can_refresh}
        refreshing={@refreshing}
      />

      <p :if={@case_record.affected_packages == []} class="text-sm text-base-content/60">
        No affected packages yet.
      </p>

      <.inline_suggestions
        case_record={@raw_case_record}
        section_id="affected"
        current_user={@current_user}
        can_resolve={@can_resolve}
      />
    </div>
    """
  end

  # One card per affected product, in one shape. Channels are always visible —
  # they are what the section is for — while boundary facts and program files
  # fold away without taking their headers, counts or buttons with them, so no
  # verb is ever behind a toggle. Editing the product's own fields opens the
  # shared child modal, like every other edit in the section.
  attr :package, :map, required: true
  attr :mode, :atom, required: true
  attr :marks, :map, required: true
  attr :can_refresh, :boolean, required: true
  attr :refreshing, :boolean, required: true

  defp affected_package_card(assigns) do
    assigns =
      assign(assigns,
        channels: Display.channel_derivations(assigns.package),
        editable?:
          assigns.mode != :view and assigns.package.id not in assigns.marks.phantom and
            assigns.package.id not in assigns.marks.deleted,
        issues: Display.derivation_issues(assigns.package)
      )

    ~H"""
    <.panel>
      <:title>Affected — {@package.vendor} / {@package.product}</:title>
      <:actions>
        <.proposal_marks row_id={@package.id} marks={@marks} />
        <button
          :if={@editable?}
          class="link link-hover text-primary"
          phx-click="edit_child"
          phx-value-type="package"
          phx-value-id={@package.id}
        >
          Edit
        </button>
        <button
          :if={@editable?}
          class="link link-hover text-base-content/50 hover:text-error"
          phx-click="remove_child"
          phx-value-type="package"
          phx-value-id={@package.id}
          data-confirm={
            if @mode == :propose,
              do: "Propose removing this package?",
              else: "Remove this package with all its channels and boundary facts?"
          }
        >
          {if @mode == :propose, do: "Propose removal", else: "Remove"}
        </button>
      </:actions>

      <AffectedComponents.product_meta
        repo_url={@package.repo_url}
        notes={product_notes(@package)}
      />

      <%!-- A stale or failing derivation makes every range below it suspect, so
            it is stated once at the top rather than repeated per channel. --%>
      <p :if={@issues != []} class="mb-2 text-xs text-warning">
        ⚠ {Enum.join(@issues, " · ")}
      </p>

      <.card_section_header title="Ships as">
        <:actions>
          <span class="flex items-center gap-3">
            <AffectedComponents.derivation_status
              state={@package.derivation_state}
              at={@package.derivation_cached_at}
              can_refresh={@can_refresh}
              refreshing={@refreshing}
            />
            <button
              :if={@mode != :view and @package.id not in @marks.phantom}
              class="link link-hover text-primary text-xs"
              phx-click="new_child"
              phx-value-type="channel"
              phx-value-affected_package_id={@package.id}
            >
              {if @mode == :propose, do: "Propose a channel", else: "Add channel"}
            </button>
          </span>
        </:actions>
      </.card_section_header>

      <div class="space-y-4">
        <AffectedComponents.channel_block
          :for={{channel, derived} <- @channels}
          id={"channel-#{channel.id}"}
          purl={channel.purl}
          fallback={channel.domain || channel.name}
          subpath={channel.subpath}
          versions={derived.versions}
          timeline={derived.timeline}
          timeline_id={"channel-timeline-#{channel.id}"}
          muted={channel.id in @marks.deleted}
        >
          <:badges>
            <span :if={Display.overridden_note(channel) != ""} class="badge badge-warning badge-xs">
              {Display.overridden_note(channel)}
            </span>
            <.proposal_marks row_id={channel.id} marks={@marks} />
          </:badges>
          <:actions :if={@mode != :view}>
            <.row_actions
              row_id={channel.id}
              type="channel"
              noun="channel"
              mode={@mode}
              marks={@marks}
            />
          </:actions>
          <:problem :if={derived.pending? or derived.issues != []}>
            <p class="mt-1 text-xs text-warning">
              ⚠ {channel_problem(derived)}
            </p>
          </:problem>
        </AffectedComponents.channel_block>
      </div>

      <p :if={@package.channels == []} class="text-sm text-base-content/60">
        Nowhere to ship yet — add the registries and repositories this product is published
        through.
      </p>

      <.disclosure
        id={"affected-boundary-#{@package.id}"}
        title="Boundary facts"
        count={length(@package.version_events)}
      >
        <:actions>
          <button
            :if={@mode != :view and @package.id not in @marks.phantom}
            class="link link-hover text-primary"
            phx-click="new_child"
            phx-value-type="event"
            phx-value-affected_package_id={@package.id}
          >
            {if @mode == :propose, do: "Propose a boundary", else: "Add boundary"}
          </button>
        </:actions>
        <:empty>Where the flaw entered and left this product — no facts recorded yet.</:empty>

        <AffectedComponents.boundary_fact
          :for={event <- @package.version_events}
          event={event.event}
          reference={Display.boundary_label(event)}
          title={event.commit_sha}
          scope={event.package_channel_id && scoped_channel_label(@package, event)}
          note={event.note}
          muted={event.id in @marks.deleted}
        >
          <:badges><.proposal_marks row_id={event.id} marks={@marks} /></:badges>
          <:actions :if={@mode != :view}>
            <.row_actions
              row_id={event.id}
              type="event"
              noun="boundary fact"
              mode={@mode}
              marks={@marks}
            />
          </:actions>
        </AffectedComponents.boundary_fact>
      </.disclosure>

      <.disclosure
        id={"affected-files-#{@package.id}"}
        title="Program files"
        count={length(@package.program_files)}
      >
        <:empty>The files carrying the flaw — none recorded yet.</:empty>
        <AffectedComponents.program_file
          :for={file <- @package.program_files}
          path={file.path}
          modules={file.modules}
          routines={file.routines}
        />
      </.disclosure>
    </.panel>
    """
  end

  # Standing exceptions that change how a product's versions are read.
  defp product_notes(package) do
    Enum.filter(
      [
        package.allow_unreleased_fix && "allows unreleased fixes",
        !package.include_prereleases && "pre-releases excluded"
      ],
      & &1
    )
  end

  defp channel_problem(%{issues: [_ | _] = issues}), do: Enum.join(issues, " · ")
  defp channel_problem(_pending), do: "fix has no containing release yet"

  attr :id, :string, required: true
  attr :heading, :string, required: true
  attr :type, :string, required: true
  attr :add_label, :string, required: true
  attr :rows, :list, required: true
  attr :mode, :atom, required: true
  attr :marks, :map, required: true, doc: "phantom/deleted row-id sets from the projection"

  attr :sort_event, :string,
    default: nil,
    doc: "enables drag & drop reordering, pushing this event with the row ids"

  attr :raw_case_record, :map, required: true
  attr :current_user, :map, required: true
  attr :can_resolve, :boolean, required: true

  attr :has_footer?, :boolean,
    default: false,
    doc: "whether the footer slot will render anything — suppresses the empty state"

  slot :row, required: true
  slot :footer, doc: "read-only content below the editable rows (e.g. derived references)"

  defp rows_section(assigns) do
    assigns = assign(assigns, :sortable, assigns.mode == :edit and assigns.sort_event != nil)

    ~H"""
    <.panel id={@id}>
      <:title>{@heading}</:title>
      <:actions>
        <button
          :if={@mode != :view}
          class="link link-hover text-primary"
          phx-click="new_child"
          phx-value-type={@type}
        >
          {@add_label}
        </button>
      </:actions>
      <ul
        id={"#{@id}-rows"}
        class="space-y-1"
        phx-hook={@sortable && "DragSort"}
        data-sort-event={@sortable && @sort_event}
      >
        <li
          :for={row <- @rows}
          id={"#{@id}-row-#{row.id}"}
          class="flex items-center justify-between gap-2 py-1 border-b border-base-200"
          data-drag-id={@sortable && row.id}
        >
          <div class={[
            "flex items-center gap-2",
            row.id in @marks.deleted && "line-through opacity-60"
          ]}>
            <span
              :if={@sortable}
              data-drag-handle
              class="cursor-grab text-base-content/40 select-none"
              title="Drag to reorder"
            >
              ⠿
            </span>
            <.row_bullet :if={not @sortable} />
            <div>{render_slot(@row, row)}</div>
            <.proposal_marks row_id={row.id} marks={@marks} />
          </div>
          <div
            :if={@mode != :view and row.id not in @marks.phantom and row.id not in @marks.deleted}
            class="flex gap-1 shrink-0"
          >
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
              data-confirm={if @mode == :propose, do: "Propose removing this row?", else: "Remove?"}
            >
              {if @mode == :propose, do: "Propose removal", else: "Remove"}
            </button>
          </div>
        </li>
      </ul>
      <p :if={@rows == [] and not @has_footer?} class="text-sm text-base-content/60">None yet.</p>

      {render_slot(@footer)}

      <.inline_suggestions
        case_record={@raw_case_record}
        section_id={@id}
        current_user={@current_user}
        can_resolve={@can_resolve}
      />
    </.panel>
    """
  end

  defp row_bullet(assigns) do
    ~H"""
    <span aria-hidden="true" class="h-[5px] w-[5px] flex-shrink-0 rounded-[1px] bg-base-content/35"></span>
    """
  end

  # The references the record adds for itself. They are not rows: nothing here
  # is editable, sortable or removable, so they sit below the stored list under
  # their own rule rather than mixing into it.
  attr :refs, :list, required: true

  defp derived_references(assigns) do
    ~H"""
    <div :if={@refs != []} class="mt-2 border-t border-dashed border-base-300 pt-2">
      <p class="mb-1 text-[0.62rem] font-bold uppercase tracking-wide text-base-content/50">
        added on publish
      </p>
      <div :for={ref <- @refs} class="flex items-center gap-2 py-0.5 text-sm opacity-70">
        <.row_bullet />
        <CveView.reference url={ref.url} tags={ref.tags} pills={:all} />
      </div>
    </div>
    """
  end

  defp reports_section(assigns) do
    ~H"""
    <.panel>
      <:title>Reports ({length(@case_record.vulnerability_reports)})</:title>
      <:actions>
        <.link :if={@triage?} navigate={~p"/reports"} class="link link-hover text-primary">
          Report triage
        </.link>
      </:actions>

      <%!-- The queue's row, at rail width: same state vocabulary and payload
            treatment, with the body clamped tighter and no decision bar —
            reports are acted on in triage, read here. --%>
      <div
        :for={report <- Enum.sort_by(@case_record.vulnerability_reports, & &1.inserted_at, DateTime)}
        class="rounded-lg border border-base-300 bg-base-300/30 p-3 text-sm mb-2 last:mb-0"
      >
        <div class="flex items-start justify-between gap-2">
          <span class="font-semibold">{report.summary}</span>
          <.state
            dot={report_dot_class(report.state)}
            class={["text-xs shrink-0", report_text_class(report.state)]}
          >
            {Phoenix.Naming.humanize(report.state)}
          </.state>
        </div>

        <div class="flex items-center gap-1.5 text-xs text-base-content/60">
          <.user_badge
            user={report.reporter}
            class="items-center"
            name_class="text-base-content/60"
          />
          <span>· {relative_time(report.inserted_at)}</span>
        </div>

        <p :if={report.triage_notes} class="text-xs text-base-content/70 italic">
          {report.triage_notes}
        </p>

        <div class="mt-2">
          <.report_payload
            payload={report.report_json}
            report_id={report.id}
            expanded?={MapSet.member?(@expanded_payloads, report.id)}
            toggle="toggle_payload"
            body_class="max-h-24 overflow-y-auto"
            json_class="max-h-60"
          />
        </div>
      </div>
    </.panel>
    """
  end

  defp report_dot_class(:submitted), do: "bg-warning"
  defp report_dot_class(:triaged), do: "bg-info"
  defp report_dot_class(:accepted), do: "bg-success"
  defp report_dot_class(:rejected), do: "bg-error"
  defp report_dot_class(_other), do: "bg-base-content/30"

  defp report_text_class(:submitted), do: "text-warning"
  defp report_text_class(:triaged), do: "text-info"
  defp report_text_class(:accepted), do: "text-success"
  defp report_text_class(:rejected), do: "text-base-content/50"
  defp report_text_class(_other), do: "text-base-content/60"

  # The User read policy is self-or-POC: a supporter sees the report through
  # their case assignment but not the reporter account behind it.
  # The User read policy allows loads through case-scoped relationships, but
  # field policies hide everything except :name from non-POC viewers - and
  # a forbidden email is an Ash.ForbiddenField struct, not nil.
  # Board D: a right-side slide-over over a scrim, with hairline text tabs
  # (Validation / Rendered JSON / Diff to published) and the lifecycle footer.
  defp preview_overlay(assigns) do
    ~H"""
    <div class="fixed inset-0 z-40" phx-window-keydown="close_preview" phx-key="escape">
      <div class="absolute inset-0 overlay-scrim" phx-click="close_preview"></div>
      <aside class="absolute inset-y-0 right-0 flex w-full max-w-[35rem] flex-col border-l border-base-300 bg-base-200">
        <div class="px-5 pt-5">
          <div class="flex items-center justify-between">
            <h3 class="font-bold">
              Record preview{if @case_record.cve_id, do: " — #{@case_record.cve_id}"}
            </h3>
            <button class="btn btn-ghost btn-xs text-base-content/60" phx-click="close_preview">
              ✕
            </button>
          </div>
          <.tab_bar select="preview_tab" class="mt-2">
            <:tab value="validation" active={@preview_tab}>Validation</:tab>
            <:tab value="json" active={@preview_tab}>Rendered JSON</:tab>
            <:tab :if={@amendment} value="diff" active={@preview_tab}>Diff to published</:tab>
            <:actions>
              <button
                class="link link-hover pb-2 text-xs text-primary"
                phx-click="preview"
                disabled={@preview == :loading}
              >
                {if @preview == :loading, do: "Rendering…", else: "Re-render"}
              </button>
            </:actions>
          </.tab_bar>
        </div>

        <div class="flex-1 overflow-y-auto px-5 py-4">
          <div :if={@preview_tab == "validation"}>
            <p :if={@preview == :loading} class="text-sm text-base-content/60">Rendering…</p>
            <div :if={is_map(@preview)}>
              <.validation_checklist rows={validation_rows(@preview, @validation)}>
                <:jump :let={row}>
                  <.link
                    href={"##{row.section}"}
                    phx-click="close_preview"
                    class="link link-hover text-xs text-primary"
                  >
                    Go to {row.section}
                  </.link>
                </:jump>
              </.validation_checklist>
              <p :if={@preview.overrides_applied != []} class="mt-3 text-xs text-base-content/50">
                Overrides applied: {Enum.join(@preview.overrides_applied, ", ")}
              </p>
            </div>
          </div>

          <div :if={@preview_tab == "json"}>
            <p :if={@preview == :loading} class="text-sm text-base-content/60">Rendering…</p>
            <.code_block :if={is_map(@preview)} source={pretty_json(@preview.cve_record)} />
          </div>

          <div :if={@preview_tab == "diff"}>
            <p :if={@diff == :loading} class="text-sm text-base-content/60">Diffing…</p>
            <div :if={is_list(@diff)} class="space-y-2">
              <p :if={not Diff.changed?(@diff)} class="text-sm text-base-content/60">
                No changes against the published record.
              </p>
              <.code_block
                :if={Diff.changed?(@diff)}
                source={Enum.map_join(@diff, "\n", &diff_line_text/1)}
                language="diff"
              />
            </div>
          </div>
        </div>

        <div
          :if={is_map(@preview)}
          class="flex flex-wrap items-center gap-3 border-t border-base-300 px-5 py-4"
        >
          <.lifecycle_buttons
            case_record={@case_record}
            current_user={@current_user}
            include_publish={true}
            publish_blocked={blocker_count(@preview, @validation) > 0}
          />
          <span :if={blocker_count(@preview, @validation) > 0} class="text-xs text-base-content/50">
            {blocker_note(blocker_count(@preview, @validation), @case_record.state)}
          </span>
        </div>
      </aside>
    </div>
    """
  end

  # One row per validation check (✓ when its validator produced no errors)
  # followed by one row per render blocker; the ✗ rows are what the footer's
  # blocker count refers to.
  @validators [schema: "CVE record schema", cvelint: "cvelint", hex: "Hex packages exist"]

  defp validation_rows(preview, validation) do
    errors = (validation && validation.errors) || []
    {eef_errors, catalog_errors} = Enum.split_with(errors, &(&1.source == :eef))

    # Each validator shows a ✓ pass row or one ✗ row per finding; EEF policy
    # errors and render blockers each get their own ✗ row. Every ✗ links to the
    # section that fixes it when we can map the finding to one.
    validator_rows(catalog_errors) ++
      Enum.map(eef_errors, &%{ok: false, text: &1.message, section: error_section(&1)}) ++
      Enum.map(preview.blockers, fn blocker ->
        %{ok: false, text: blocker, section: blocker_section(blocker)}
      end)
  end

  defp validator_rows(errors) do
    Enum.flat_map(@validators, fn {source, label} ->
      case Enum.filter(errors, &(&1.source == source)) do
        [] ->
          [%{ok: true, text: label, section: nil}]

        failures ->
          Enum.map(
            failures,
            &%{ok: false, text: "#{label}: #{&1.message}", section: error_section(&1)}
          )
      end
    end)
  end

  # The workspace section a validation finding's code points at — cvelint
  # (github.com/mprpic/cvelint ruleset) and EEF policy codes. A finding whose
  # code we don't map (or that has no code) renders without a link.
  @section_by_code [
                     {"references", ~w(E001 E002 E010 E017)},
                     {"affected", ~w(E006 E007 E008 E009 E011 E013 E014 HEX001)},
                     {"summary", ~w(E003 E004 E016 E019 E020 EEF001)},
                     {"severity", ~w(E005 E018 EEF002)},
                     {"weaknesses", ~w(EEF004)},
                     {"impacts", ~w(EEF005)}
                   ]
                   |> Enum.flat_map(fn {section, codes} -> Enum.map(codes, &{&1, section}) end)
                   |> Map.new()

  defp error_section(%{code: code}), do: Map.get(@section_by_code, code)

  defp blocker_count(preview, validation), do: Enum.count(validation_rows(preview, validation), &(not &1.ok))

  defp blocker_note(count, state) do
    noun = if count == 1, do: "blocker", else: "blockers"
    clause = if state == :approved, do: "blocking publish", else: "resolves after approval"
    "#{count} #{noun} · #{clause}"
  end

  # Maps a render blocker to the workspace section that fixes it; nil when
  # the fix is a band action (e.g. assigning a CVE ID), not a section.
  defp blocker_section(blocker) do
    cond do
      blocker =~ "CVE ID" -> nil
      blocker =~ "CVSS" -> "severity"
      blocker =~ "title" or blocker =~ "description" -> "summary"
      blocker =~ "reference" -> "references"
      true -> "affected"
    end
  end

  # Resolved suggestions (accepted, declined, superseded, withdrawn) are not
  # in the mock; kept reachable via one collapsed, quiet disclosure at the
  # bottom of the center column, out of the way — an interim placement
  # pending a dedicated Suggestions surface (see the design note).
  attr :case_record, :map, required: true
  attr :current_user, :map, required: true
  attr :can_resolve, :boolean, required: true

  defp resolved_suggestions_disclosure(assigns) do
    ~H"""
    <details id="resolved-suggestions">
      <summary class="cursor-pointer text-sm text-base-content/60">
        Resolved suggestions ({length(resolved_proposals(@case_record))})
      </summary>
      <div class="mt-2 space-y-3">
        <.resolved_proposal_card
          :for={proposal <- resolved_proposals(@case_record)}
          proposal={proposal}
        />
      </div>
    </details>
    """
  end

  defp assignments_section(assigns) do
    ~H"""
    <.panel>
      <:title>People</:title>
      <ul class="space-y-2 text-sm">
        <li
          :for={assignment <- @case_record.assignments}
          class="flex items-center justify-between gap-2"
        >
          <span class="flex min-w-0 items-center gap-2">
            <.user_badge
              user={assignment.user}
              variant={person_variant(@case_record, assignment)}
              name_class="truncate"
            />
            <span class="shrink-0 text-base-content/50">{person_role(assignment.user)}</span>
          </span>
          <button
            :if={Varsel.Cases.can_unassign_case_user?(@current_user, assignment)}
            class="btn btn-ghost btn-xs text-error"
            phx-click="unassign_user"
            phx-value-id={assignment.id}
            data-confirm="Revoke this user's access to the case?"
          >
            Remove
          </button>
        </li>
      </ul>
      <p :if={@case_record.assignments == []} class="text-sm text-base-content/60">
        No one assigned yet.
      </p>

      <form
        :if={Cases.can_assign_case_user?(@current_user, %{case_id: @case_record.id})}
        phx-submit="assign_user"
        class="flex items-center gap-2 mt-2"
      >
        <select name="user_id" required class="select select-bordered select-sm flex-1">
          <option value="">Assign a user…</option>
          <option
            :for={user <- @users}
            :if={not Enum.any?(@case_record.assignments, &(&1.user_id == user.id))}
            value={user.id}
          >
            <.user_name user={user} />
          </option>
        </select>
        <button type="submit" class="btn btn-outline btn-sm">Assign</button>
      </form>
    </.panel>
    """
  end

  # The mock's two avatar color variants, applied by assignment order (only
  # cosmetic — nothing tracks a "primary" assignee).
  defp person_variant(case_record, assignment) do
    if Enum.at(case_record.assignments, 0) == assignment, do: :a, else: :b
  end

  defp person_role(%{role: :poc}), do: "POC"
  defp person_role(%{role: :supporter}), do: "supporter"
  defp person_role(_user), do: nil

  defp close_link(assigns) do
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
      </div>
    </details>
    """
  end

  attr :records, :list, required: true

  # Two ways to take an ID, kept visibly apart: the top half is the one-click
  # default (whatever is next in the pool), the bottom half is the deliberate
  # pick. Nothing is assigned by opening this — both halves need their own
  # button, so neither path can be taken by reflex.
  defp cve_picker_modal(assigns) do
    {free, withheld} = Enum.split_with(assigns.records, &(&1.state == :reserved))

    assigns = assign(assigns, free: free, withheld: withheld)

    ~H"""
    <.modal id="cve-picker-modal" title="Assign a CVE ID" on_cancel="cancel_cve_picker">
      <div class="space-y-4">
        <div class="rounded-lg border border-base-300 bg-base-200 p-3">
          <p class="text-sm font-semibold">Take the next free ID</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            <span :if={@free != []}>
              The lowest free ID of the current year, chosen when you confirm.
            </span>
            <span :if={@free == []}>The pool is empty — reserve more IDs first.</span>
          </p>
          <button
            :if={@free != []}
            type="button"
            class="btn btn-eef btn-sm mt-2"
            phx-click="confirm_assign_cve_id"
          >
            Assign the next free ID
          </button>
        </div>

        <form
          :if={@free != [] or @withheld != []}
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

        <p :if={@free == [] and @withheld == []} class="text-sm text-base-content/60">
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

  defp child_modal(assigns) do
    ~H"""
    <.modal id="child-modal" title={@child_form.title} on_cancel="cancel_child">
      <.child_form
        child_form={@child_form}
        mode={@mode}
        catalog_options={@catalog_options}
        id="child-form"
        phx-change="validate_child"
        phx-submit="submit_child"
      >
        <:actions>
          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" phx-click="cancel_child">
              Cancel
            </button>
            <button type="submit" class="btn btn-primary btn-sm">
              {if @mode == :propose, do: "Propose", else: "Save"}
            </button>
          </div>
        </:actions>
      </.child_form>
    </.modal>
    """
  end

  # Which of the named forms a child row opens, and what each of them needs
  # beyond the changeset itself.
  attr :child_form, :map, required: true
  attr :mode, :atom, required: true
  attr :catalog_options, :any, required: true
  attr :rest, :global
  slot :actions

  defp child_form(%{child_form: %{type: "package"}} = assigns) do
    ~H"""
    <.affected_package_form form={@child_form.form} propose?={@mode == :propose} {@rest}>
      <:actions>{render_slot(@actions)}</:actions>
    </.affected_package_form>
    """
  end

  defp child_form(%{child_form: %{type: "package_" <> preset}} = assigns) do
    assigns = assign(assigns, :preset, String.to_existing_atom(preset))

    ~H"""
    <.preset_package_form
      form={@child_form.form}
      preset={@preset}
      propose?={@mode == :propose}
      {@rest}
    >
      <:actions>{render_slot(@actions)}</:actions>
    </.preset_package_form>
    """
  end

  defp child_form(%{child_form: %{type: "channel"}} = assigns) do
    ~H"""
    <.channel_form form={@child_form.form} propose?={@mode == :propose} {@rest}>
      <:actions>{render_slot(@actions)}</:actions>
    </.channel_form>
    """
  end

  defp child_form(%{child_form: %{type: "event"}} = assigns) do
    ~H"""
    <.version_event_form
      form={@child_form.form}
      channel_options={@child_form.channel_options}
      propose?={@mode == :propose}
      {@rest}
    >
      <:actions>{render_slot(@actions)}</:actions>
    </.version_event_form>
    """
  end

  defp child_form(%{child_form: %{type: "reference"}} = assigns) do
    ~H"""
    <.reference_form form={@child_form.form} propose?={@mode == :propose} {@rest}>
      <:actions>{render_slot(@actions)}</:actions>
    </.reference_form>
    """
  end

  defp child_form(%{child_form: %{type: "credit"}} = assigns) do
    ~H"""
    <.credit_form form={@child_form.form} propose?={@mode == :propose} {@rest}>
      <:actions>{render_slot(@actions)}</:actions>
    </.credit_form>
    """
  end

  defp child_form(%{child_form: %{type: "weakness"}} = assigns) do
    ~H"""
    <.weakness_form
      form={@child_form.form}
      catalog_options={@catalog_options}
      propose?={@mode == :propose}
      {@rest}
    >
      <:actions>{render_slot(@actions)}</:actions>
    </.weakness_form>
    """
  end

  defp child_form(%{child_form: %{type: "impact"}} = assigns) do
    ~H"""
    <.impact_form
      form={@child_form.form}
      catalog_options={@catalog_options}
      propose?={@mode == :propose}
      {@rest}
    >
      <:actions>{render_slot(@actions)}</:actions>
    </.impact_form>
    """
  end

  # Board C opens a package's own field edit (vendor/product/repo/program
  # files) in place inside its expanded card, not the centered child modal —
  # true only for an *update* form (a brand-new package still has no card to
  # expand into, so "Add package" stays on the modal).

  defp update_child_form(socket, fun) do
    child_form = socket.assigns.child_form
    form = child_form.form.source |> fun.() |> to_form()
    assign(socket, child_form: %{child_form | form: form})
  end

  # Channels of the boundary's package, for scoping a fact to one channel at
  # creation (the :edit action deliberately does not re-scope).
  defp channel_options("event", %{"affected_package_id" => package_id}, socket) do
    case Enum.find(socket.assigns.case_record.affected_packages, &(&1.id == package_id)) do
      nil ->
        []

      package ->
        Enum.map(package.channels, &{Display.channel_label(package, &1), &1.id})
    end
  end

  defp channel_options(_type, _params, _socket), do: []

  defp scoped_channel_label(package, event) do
    case Enum.find(package.channels, &(&1.id == event.package_channel_id)) do
      nil -> "(removed channel)"
      channel -> Display.channel_label(package, channel)
    end
  end

  # The CWE/CAPEC catalogs back the classification datalists; load them once
  # per LiveView, only when a weakness/impact modal first opens.
  defp ensure_catalog_options(socket, type) when type in ["weakness", "impact"] do
    if socket.assigns.catalog_options do
      socket
    else
      weaknesses =
        Varsel.CWE.query_to_list_weaknesses()
        |> Ash.Query.load([:cwe_id, :name])
        |> Ash.Query.sort(:cwe_id)
        |> Ash.read!()
        |> Enum.map(&{&1.cwe_id, &1.name})

      attack_patterns =
        Varsel.CAPEC.query_to_list_attack_patterns()
        |> Ash.Query.load([:capec_id, :name])
        |> Ash.Query.sort(:capec_id)
        |> Ash.read!()
        |> Enum.map(&{&1.capec_id, &1.name})

      assign(socket, catalog_options: %{cwe: weaknesses, capec: attack_patterns})
    end
  end

  defp ensure_catalog_options(socket, _type), do: socket

  # Pushed by the DragSort hook: rewrite positions to match the new id order.
  defp reorder_rows(socket, rows, edit_fun, ids) do
    actor = socket.assigns.current_user

    result =
      ids
      |> Enum.with_index()
      |> Enum.reduce_while(:ok, fn {id, index}, :ok ->
        case move_row(rows, id, index, edit_fun, actor) do
          :ok -> {:cont, :ok}
          {:error, error} -> {:halt, {:error, error}}
        end
      end)

    socket =
      case result do
        :ok -> socket
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  defp move_row(rows, id, index, edit_fun, actor) do
    case Enum.find(rows, &(&1.id == id)) do
      nil ->
        # Not in the loaded list (raced with a concurrent change): skip.
        :ok

      %{position: ^index} ->
        :ok

      row ->
        case edit_fun.(row, %{position: index}, actor: actor) do
          {:ok, _row} -> :ok
          {:error, error} -> {:error, error}
        end
    end
  end

  # New references/credits append to the end; ordering is drag & drop.
  defp put_append_position(parent, type, case_record) when type in ["reference", "credit"] do
    rows =
      case type do
        "reference" -> case_record.references
        "credit" -> case_record.credits
      end

    next =
      case rows do
        [] -> 0
        rows -> rows |> Enum.map(& &1.position) |> Enum.max() |> Kernel.+(1)
      end

    Map.put(parent, "position", next)
  end

  defp put_append_position(parent, _type, _case_record), do: parent

  defp modal_title(verb, title, socket) do
    case socket.assigns.mode do
      :propose -> "#{verb} #{title} (as a proposal)"
      _edit -> "#{verb} #{title}"
    end
  end

  # Rows in propose mode come from the projection, keyed by the same ids the
  # templates render (phantom rows carry their proposal's id and are never
  # editable, so lookups only see real rows).
  defp find_projected_row(display_case, type, id) do
    rows =
      case type do
        "package" ->
          display_case.affected_packages

        "channel" ->
          Enum.flat_map(display_case.affected_packages, & &1.channels)

        "event" ->
          Enum.flat_map(display_case.affected_packages, & &1.version_events)

        "reference" ->
          display_case.references

        "credit" ->
          display_case.credits
      end

    Enum.find(rows, &(&1.id == id)) || raise "row #{id} not found in projection"
  end
end
