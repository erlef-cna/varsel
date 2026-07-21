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

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.CaseComponents

  alias Varsel.Accounts
  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseImpact
  alias Varsel.Cases.CaseReference
  alias Varsel.Cases.CaseWeakness
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.Projection
  alias Varsel.Cases.Proposable
  alias Varsel.Cases.Publication
  alias Varsel.Cases.Readiness
  alias Varsel.Cases.Render.Channel
  alias Varsel.Cases.Render.Diff
  alias Varsel.Cases.VersionEvent
  alias Varsel.Types.CVSS

  @case_loads [
    :cve_id,
    :cve_record,
    assignments: [:user],
    references: [],
    credits: [],
    weaknesses: [:weakness],
    impacts: [:attack_pattern],
    affected_packages: [:channels, :version_events],
    proposals: [:author, :resolved_by],
    comments: [:author],
    # The report read policy is POC-only; supporters get an empty list here.
    vulnerability_reports: [:reporter]
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

  # Comma/newline separated text inputs that become {:array, :string} attributes.
  @list_params %{
    "package" => ~w(platforms),
    "package_otp" => ~w(applications fixed_commits),
    "package_elixir" => ~w(applications fixed_commits),
    "package_gleam" => ~w(fixed_commits),
    "channel" => ~w(tag_suffixes),
    "reference" => ~w(tags)
  }

  # The package modal types sharing the program-files textarea.
  @package_types ~w(package package_otp package_elixir package_gleam)

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
        child_form: nil,
        preview: nil,
        preview_open?: false,
        preview_tab: "validation",
        diff: nil,
        users: nil,
        catalog_options: nil
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

  def handle_event("assign_cve_id", _params, socket) do
    socket =
      case Cases.assign_case_cve_id(socket.assigns.case_record, %{}, actor: socket.assigns.current_user) do
        {:ok, _case_record} -> put_flash(socket, :info, "CVE ID assigned.")
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
        {:ok, _case_record} -> put_flash(socket, :info, "Case closed.")
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
       Cases.render_case_preview!(%{id: case_record.id}, actor: actor)
     end)}
  end

  def handle_event("close_preview", _params, socket) do
    {:noreply, assign(socket, preview_open?: false, preview: nil, diff: nil)}
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
    params = normalize_child_params(type, params, socket.assigns.child_form.parent)
    form = AshPhoenix.Form.validate(form, params)

    {:noreply, assign(socket, child_form: %{socket.assigns.child_form | form: form})}
  end

  def handle_event("submit_child", %{"child" => params} = raw, socket) do
    %{form: form, type: type} = socket.assigns.child_form
    params = normalize_child_params(type, params, socket.assigns.child_form.parent)

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
  def handle_async(:preview, {:ok, preview}, socket) do
    {:noreply, assign(socket, preview: preview)}
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
      # Re-fetch with the actor so the diff is as authorized as the page load.
      case_record = Cases.get_case!(case_record.id, actor: actor)
      published = Publication.published_cna(case_record) || %{}
      {:ok, %{result: result}} = Publication.render(case_record)
      Diff.lines(published, result.cna)
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

    users =
      if poc?(actor) do
        Accounts.list_users!(actor: actor)
      else
        []
      end

    assign(socket,
      case_record: case_record,
      display_case: display_case,
      projection: projection,
      mode: mode,
      content_form: content_form,
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

  # Splits comma/newline separated list inputs and merges the parent ids.
  defp normalize_child_params(type, params, parent) do
    params =
      params
      |> Map.merge(parent)
      |> merge_reference_tags(type)
      |> parse_classification_id(type)
      |> parse_qualifiers(type)
      |> parse_program_files(type)

    Enum.reduce(Map.get(@list_params, type, []), params, fn key, params ->
      case params[key] do
        value when is_binary(value) ->
          Map.put(params, key, split_list(value))

        _other ->
          params
      end
    end)
  end

  # Program files come from nested forms as an indexed map of rows; the
  # module/routine text inputs within each row are comma separated. The
  # indexed-map shape stays as-is for AshPhoenix's nested-form tracking.
  defp parse_program_files(%{"program_files" => %{} = files} = params, type) when type in @package_types do
    files =
      Map.new(files, fn {index, file} ->
        {index, file |> split_file_list("modules") |> split_file_list("routines")}
      end)

    Map.put(params, "program_files", files)
  end

  defp parse_program_files(params, _type), do: params

  defp split_file_list(file, key) do
    case file[key] do
      value when is_binary(value) -> Map.put(file, key, split_list(value))
      _other -> file
    end
  end

  # The nested program-file rows in their canonical stored shape: ordered by
  # index, internal form-tracking keys and pathless (just-added, empty) rows
  # dropped. Used where params leave the form machinery — proposal payloads
  # and the projected-row diff.
  defp program_files_list(%{} = files) do
    files
    |> Enum.sort_by(fn {index, _file} -> String.to_integer(index) end)
    |> Enum.map(fn {_index, file} ->
      %{
        "path" => file["path"],
        "modules" => file["modules"] || [],
        "routines" => file["routines"] || []
      }
    end)
    |> Enum.reject(&(&1["path"] in [nil, ""]))
  end

  # Channel qualifiers arrive as "key=value, key=value" text.
  defp parse_qualifiers(%{"qualifiers" => value} = params, "channel") when is_binary(value) do
    qualifiers =
      value
      |> split_list()
      |> Enum.flat_map(fn pair ->
        case String.split(pair, "=", parts: 2) do
          [key, value] -> [{String.trim(key), String.trim(value)}]
          _no_value -> []
        end
      end)
      |> Map.new()

    Map.put(params, "qualifiers", qualifiers)
  end

  defp parse_qualifiers(params, _type), do: params

  ## ------------------------------------------------------ proposal building

  # Content saved in propose mode: one :set proposal per field changed
  # against the *projection* — untouched proposed values create nothing,
  # changing one counters the proposal that put it there.
  defp propose_content_changes(socket, params, reasoning) do
    %{display_case: display_case, projection: projection, case_record: case_record} =
      socket.assigns

    proposals =
      for field <- Proposable.fields(Cases.Case),
          key = to_string(field),
          Map.has_key?(params, key),
          changed_value?(Map.get(display_case, field), params[key]) do
        %{
          case_id: case_record.id,
          target: :case,
          operation: :set,
          field_name: key,
          proposed_value: %{"value" => params[key]},
          reasoning: reasoning,
          parent_proposal_id: countered_id(projection, :case, nil, key)
        }
      end

    create_proposals(socket, proposals)
  end

  defp countered_id(nil, _target, _target_id, _field), do: nil

  defp countered_id(projection, target, target_id, field) do
    case Projection.countered(projection, target, target_id, field) do
      nil -> nil
      proposal -> proposal.id
    end
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
          Map.put(params, "program_files", program_files_list(files))

        params ->
          params
      end

    proposals =
      case form.source.type do
        :create -> child_insert_proposals(config, case_id, params, reasoning)
        :update -> child_set_proposals(socket, config, case_id, form, params, reasoning)
      end

    socket = assign(socket, child_form: nil)
    create_proposals(socket, proposals)
  end

  defp child_insert_proposals(config, case_id, params, reasoning) do
    allowed =
      case config[:preset] do
        nil ->
          Proposable.fields(config.resource) ++ Proposable.insert_extra_fields(config.resource)

        preset ->
          Preset.payload_fields(preset)
      end

    payload =
      params
      |> Map.take(Enum.map(allowed, &to_string/1))
      |> Enum.reject(fn {_key, value} -> value in [nil, "", []] end)
      |> Map.new()

    payload =
      case config[:preset] do
        nil -> payload
        preset -> Map.put(payload, "preset", to_string(preset))
      end

    [
      %{
        case_id: case_id,
        target: config.target,
        operation: :insert,
        target_id: params["affected_package_id"],
        proposed_value: %{"value" => payload},
        reasoning: reasoning
      }
    ]
  end

  # The edit form was built from the projected row, so the diff yields only
  # genuinely new changes; counters link to the countered proposal.
  defp child_set_proposals(socket, config, case_id, form, params, reasoning) do
    row = form.source.data
    projection = socket.assigns.projection

    for field <- Proposable.set_fields(config.resource),
        key = to_string(field),
        Map.has_key?(params, key),
        changed_value?(Map.get(row, field), params[key]) do
      %{
        case_id: case_id,
        target: config.target,
        operation: :set,
        target_id: row.id,
        field_name: key,
        proposed_value: %{"value" => params[key]},
        reasoning: reasoning,
        parent_proposal_id: countered_id(projection, config.target, row.id, key)
      }
    end
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

  # Loose equality between a stored value and its form-param representation
  # (enum atoms vs strings, integers vs digits, CVSS structs vs vectors, nil
  # vs empty input).
  defp changed_value?(current, param), do: comparable(current) != comparable(param)

  defp comparable(%CVSS{vector: vector}), do: vector

  defp comparable(%Varsel.Cases.AffectedPackage.ProgramFile{} = file) do
    %{"path" => file.path, "modules" => file.modules, "routines" => file.routines}
  end

  defp comparable(nil), do: ""
  defp comparable(value) when is_list(value), do: Enum.map(value, &comparable/1)
  defp comparable(value) when is_map(value), do: value
  defp comparable(value), do: to_string(value)

  # The classification inputs autocomplete to "CWE-613 Insufficient Session
  # Expiration"-style datalist values; extract the numeric id (bare numbers
  # keep working too).
  defp parse_classification_id(params, "weakness"), do: extract_numeric_id(params, "cwe_id")
  defp parse_classification_id(params, "impact"), do: extract_numeric_id(params, "capec_id")
  defp parse_classification_id(params, _type), do: params

  defp extract_numeric_id(params, key) do
    with value when is_binary(value) <- params[key],
         [digits] <- Regex.run(~r/\d+/, value) do
      Map.put(params, key, digits)
    else
      _no_number -> params
    end
  end

  # Reference tags arrive as a checkbox list (with an empty sentinel) plus a
  # comma-separated custom_tags text input; merge them into one tags list.
  defp merge_reference_tags(params, "reference") do
    standard = params |> Map.get("tags", []) |> List.wrap() |> Enum.reject(&(&1 == ""))
    custom = split_list(params["custom_tags"] || "")

    params
    |> Map.put("tags", Enum.uniq(standard ++ custom))
    |> Map.delete("custom_tags")
  end

  defp merge_reference_tags(params, _type), do: params

  defp split_list(value) do
    value
    |> String.split(~r/[\n,]/, trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
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

  # An amendment: the backing CVE record already carries a published CNA
  # container, so publishing pushes an update — a diff against it is meaningful.
  defp amendment?(case_record) do
    match?(
      %{cve_record: %{cve_json: %{"containers" => %{"cna" => %{}}}}},
      case_record
    )
  end

  defp can_edit?(case_record, user), do: editable?(case_record) and (poc?(user) or assigned?(case_record, user))

  # Proposals stay possible while the content is frozen (approved/published) —
  # that is the post-publish enrichment flow; only closed cases refuse them.
  defp can_propose?(case_record, user), do: case_record.state != :closed and (poc?(user) or assigned?(case_record, user))

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

  defp diff_line_class({:del, _line}), do: "bg-error/10 text-error"
  defp diff_line_class({:ins, _line}), do: "bg-success/10 text-success"
  defp diff_line_class({:skip, _count}), do: "text-base-content/40"
  defp diff_line_class({:eq, _line}), do: "text-base-content/70"

  defp diff_line_text({:del, line}), do: "- " <> line
  defp diff_line_text({:ins, line}), do: "+ " <> line
  defp diff_line_text({:eq, line}), do: "  " <> line
  defp diff_line_text({:skip, count}), do: "  ⋯ #{count} unchanged lines"

  defp proposal_badge_class(:open), do: "badge-warning"
  defp proposal_badge_class(:accepted), do: "badge-success"
  defp proposal_badge_class(:declined), do: "badge-error"
  defp proposal_badge_class(_other), do: "badge-ghost"

  defp humanize_action(action), do: String.replace(action, "_", " ")

  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")

  defp pretty_json(nil), do: ""
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
    <Layouts.flash_group flash={@flash} />

    <div class={@preview_open? && "opacity-45"}>
      <div class="console-band">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-5 flex flex-wrap items-start justify-between gap-x-8 gap-y-4">
          <div class="min-w-0">
            <p class="eef-eyebrow mb-1">
              Case <span :if={@case_record.cve_id} class="font-mono">· {@case_record.cve_id}</span>
              <span :if={is_nil(@case_record.cve_id)} class="opacity-60">· no CVE ID assigned</span>
              <span class="text-base-content/50">
                · draft opened {Calendar.strftime(@case_record.inserted_at, "%b %-d, %Y")}
              </span>
            </p>
            <h1 class="text-xl sm:text-2xl font-bold leading-tight">
              {@case_record.title || "Untitled case"}
            </h1>
            <.lifecycle_stepper state={@case_record.state} />
          </div>
          <div class="flex flex-wrap items-center justify-end gap-2 pt-1.5">
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
          </div>
        </div>
      </div>

      <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-6">
        <p :if={@mode == :propose} class="text-sm text-base-content/60 mb-4">
          Suggesting: open suggestions are shown as if accepted; your edits become new suggestions.
        </p>

        <div class="grid lg:grid-cols-[9.5rem_minmax(0,1fr)_18.5rem] gap-6 items-start">
          <.section_nav
            sections={workspace_sections(@display_case, @case_record.proposals)}
            class="hidden lg:block lg:sticky lg:top-4"
          />

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
                <a
                  href={"https://cwe.mitre.org/data/definitions/#{weakness.cwe_id}.html"}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="link font-mono"
                >
                  CWE-{weakness.cwe_id}
                </a>
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
                <a
                  href={"https://capec.mitre.org/data/definitions/#{impact.capec_id}.html"}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="link font-mono"
                >
                  CAPEC-{impact.capec_id}
                </a>
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

          <div class="space-y-4">
            <.panel id="suggestions" title="Suggestions">
              <ul :if={open_proposals(@case_record) != []} class="space-y-1.5 text-sm">
                <li :for={proposal <- open_proposals(@case_record)} class="flex items-center gap-2">
                  <span class="text-info font-bold shrink-0">◆</span>
                  <span class="truncate text-base-content/80">
                    {proposal_field_ref(proposal)}
                    <span class="text-base-content/50">— {display_name(proposal.author)}</span>
                  </span>
                  <a
                    href={"#suggestion-#{proposal.id}"}
                    class="link link-hover text-primary text-xs ml-auto shrink-0"
                  >
                    Jump
                  </a>
                </li>
              </ul>
              <p :if={open_proposals(@case_record) == []} class="text-sm text-base-content/60">
                No open suggestions.
              </p>
            </.panel>
            <.panel title="Activity">
              <form phx-submit="post_comment" class="mb-4">
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
            <.assignments_section :if={poc?(@current_user)} case_record={@case_record} users={@users} />
            <.reports_section
              :if={@case_record.vulnerability_reports != []}
              case_record={@case_record}
              poc={poc?(@current_user)}
            />
            <.close_link
              :if={poc?(@current_user) and editable?(@case_record)}
              case_record={@case_record}
            />
          </div>
        </div>

        <.child_modal
          :if={@child_form}
          child_form={@child_form}
          catalog_options={@catalog_options}
          mode={@mode}
        />
      </div>
    </div>

    <.preview_overlay
      :if={@preview_open?}
      case_record={@case_record}
      current_user={@current_user}
      preview={@preview}
      preview_tab={@preview_tab}
      diff={@diff}
      amendment={amendment?(@case_record)}
    />
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
          who: display_name(comment.author),
          at: comment.inserted_at,
          body: comment.body,
          markdown?: true
        }
      end)

    proposals =
      Enum.map(case_record.proposals, fn proposal ->
        %{
          kind: :proposal,
          who: display_name(proposal.author),
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
        :if={
          @case_record.state in [:draft, :review, :approved] and is_nil(@case_record.cve_id) and
            poc?(@current_user)
        }
        class="btn btn-sm btn-eef-quiet"
        phx-click="assign_cve_id"
      >
        Assign CVE ID
      </button>
      <button
        :if={@case_record.state == :draft}
        class="btn btn-sm btn-eef"
        phx-click="lifecycle"
        phx-value-action="request_review"
      >
        Request review
      </button>
      <button
        :if={@case_record.state == :review and poc?(@current_user)}
        class="btn btn-sm btn-eef-quiet"
        phx-click="lifecycle"
        phx-value-action="request_changes"
      >
        Request changes
      </button>
      <button
        :if={@case_record.state == :review and poc?(@current_user)}
        class="btn btn-sm btn-eef"
        phx-click="lifecycle"
        phx-value-action="approve"
      >
        Approve
      </button>
      <button
        :if={@include_publish and @case_record.state == :approved and poc?(@current_user)}
        class={["btn btn-sm btn-eef", @publish_blocked && "opacity-45"]}
        disabled={@publish_blocked}
        phx-click="lifecycle"
        phx-value-action="publish"
        data-confirm="Publish this case to MITRE?"
      >
        Publish to MITRE
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

  # Renders every open suggestion targeting one section, inline inside that
  # section's own card — the aggregate "Suggestions" section is gone; this is
  # its only rendering now, plus the rail's compact queue and the bottom
  # "Resolved suggestions" disclosure.
  attr :case_record, :map, required: true
  attr :section_id, :string, required: true
  attr :current_user, :map, required: true
  attr :can_resolve, :boolean, required: true

  defp inline_suggestions(assigns) do
    assigns =
      assign(assigns,
        suggestions: section_suggestions(assigns.case_record, assigns.section_id),
        comments: comments_by_proposal(assigns.case_record)
      )

    ~H"""
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
        <pre
          :if={proposal.operation != :set and proposal.proposed_value}
          class="mt-1 max-h-40 overflow-x-auto rounded bg-base-300 p-2 text-xs"
        >{pretty_json(proposal.proposed_value["value"])}</pre>
      </.suggestion_card>
    </div>
    """
  end

  defp content_section(assigns) do
    ~H"""
    <div :if={@content_form} class="flex justify-end mb-2">
      <.mode_pill :if={@mode == :propose} on?={true} explain={true} />
    </div>
    <.panel
      title={if @content_form, do: "Summary — editing", else: "Summary"}
      editing?={!!@content_form}
    >
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

        <div class="flex items-end gap-2 mt-4">
          <button type="submit" class={["btn btn-sm", save_button_class(@mode)]}>
            {if @mode == :propose, do: "Suggest changes", else: "Save changes"}
          </button>
          <button type="button" class="btn btn-eef-quiet btn-sm" phx-click="cancel_edit">
            Cancel
          </button>
          <input
            :if={@mode == :propose}
            type="text"
            name="reasoning"
            placeholder="Reasoning (attached to the suggestion, optional)"
            class="input input-bordered input-sm flex-1"
          />
        </div>
      </.form>

      <div :if={!@content_form} class="space-y-4">
        <.markdown :if={@case_record.description_md} content={@case_record.description_md} />
        <p :if={is_nil(@case_record.description_md)} class="text-base-content/60">
          No description yet.
        </p>

        <div :for={
          {label, content} <- [
            {"Configurations", @case_record.configurations_md},
            {"Workarounds", @case_record.workarounds_md},
            {"Solutions", @case_record.solutions_md}
          ]
        }>
          <div :if={content}>
            <h3 class="text-sm font-semibold text-base-content/70 mb-1">{label}</h3>
            <.markdown content={content} />
          </div>
        </div>
      </div>

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
  defp save_button_class(:propose), do: "btn-info text-info-content"
  defp save_button_class(_edit), do: "btn-primary"

  # The Severity card: at rest one severity chip (rating + score) beside the
  # truncated CVSS vector; "Open calculator" swaps the body for the CVSS
  # calculator as this card's own editor, with the same save-vs-suggest
  # semantics as the summary editor.
  defp severity_section(assigns) do
    ~H"""
    <div :if={@form} class="flex justify-end mb-2">
      <.mode_pill :if={@mode == :propose} on?={true} explain={true} />
    </div>
    <.panel title={if @form, do: "Severity — editing", else: "Severity"} editing?={!!@form}>
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
        <div class="flex items-end gap-2 mt-4">
          <button type="submit" class={["btn btn-sm", save_button_class(@mode)]}>
            {if @mode == :propose, do: "Suggest changes", else: "Save changes"}
          </button>
          <button type="button" class="btn btn-eef-quiet btn-sm" phx-click="cancel_edit">
            Cancel
          </button>
          <input
            :if={@mode == :propose}
            type="text"
            name="reasoning"
            placeholder="Reasoning (attached to the suggestion, optional)"
            class="input input-bordered input-sm flex-1"
          />
        </div>
      </.form>

      <div :if={!@form}>
        <div :if={@case_record.cvss_v4} class="flex min-w-0 items-center gap-3">
          <.severity_chip
            severity={@case_record.cvss_v4.severity}
            score={@case_record.cvss_v4.score}
          />
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

  defp affected_section(assigns) do
    ~H"""
    <.panel title="Affected">
      <:actions>
        <button class="link link-hover text-primary" phx-click="refresh_derivation">
          Refresh derivation
        </button>
        <div :if={@mode != :view} class="dropdown dropdown-end">
          <div tabindex="0" role="button" class="link link-hover text-primary cursor-pointer">
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

      <div
        :for={package <- @case_record.affected_packages}
        class="rounded-lg border border-base-300 bg-base-300/30 mb-4 last:mb-0"
      >
        <div class="card-body p-4">
          <div class="flex items-start justify-between">
            <div>
              <h3 class={["font-semibold", package.id in @marks.deleted && "line-through opacity-60"]}>
                {package.vendor} / {package.product}
                <span
                  :if={package.id in @marks.phantom}
                  class="badge badge-info badge-xs align-middle"
                >proposed</span>
                <span
                  :if={package.id in @marks.deleted}
                  class="badge badge-error badge-xs align-middle"
                >
                  removal proposed
                </span>
              </h3>
              <p :if={package.repo_url} class="text-sm font-mono text-base-content/70">
                {package.repo_url}
              </p>
              <p class="text-xs text-base-content/60 mt-1">
                default status: {package.default_status}
                <span :if={package.allow_unreleased_fix}>· allows unreleased fixes</span>
              </p>
            </div>
            <div
              :if={
                @mode != :view and package.id not in @marks.phantom and
                  package.id not in @marks.deleted
              }
              class="flex gap-1"
            >
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
                data-confirm={
                  if @mode == :propose,
                    do: "Propose removing this package?",
                    else: "Remove this package with all its channels and boundary facts?"
                }
              >
                {if @mode == :propose, do: "Propose removal", else: "Remove"}
              </button>
            </div>
          </div>

          <div class="mt-2">
            <div class="flex items-center justify-between">
              <h4 class="text-sm font-semibold text-base-content/70">Channels</h4>
              <button
                :if={@mode != :view and package.id not in @marks.phantom}
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
                  <td><span class="badge badge-ghost badge-sm">{channel.purl_type}</span></td>
                  <td
                    class="font-mono"
                    title={Channel.purl_string(package, channel)}
                  >
                    {channel_label(package, channel) || "—"}
                  </td>
                  <td class="text-xs text-base-content/70 font-mono">
                    {derived_versions_label(package, channel.id)}
                  </td>
                  <td class="text-xs text-base-content/60">
                    {if channel.versions_override, do: "versions overridden"}
                    {if channel.entry_override, do: "entry overridden"}
                  </td>
                  <td :if={@mode != :view} class="text-right whitespace-nowrap">
                    <button
                      :if={channel.id not in @marks.phantom and channel.id not in @marks.deleted}
                      class="btn btn-ghost btn-xs"
                      phx-click="edit_child"
                      phx-value-type="channel"
                      phx-value-id={channel.id}
                    >
                      Edit
                    </button>
                    <span :if={channel.id in @marks.phantom} class="badge badge-info badge-xs">proposed</span>
                    <span :if={channel.id in @marks.deleted} class="badge badge-error badge-xs">removal proposed</span>
                    <button
                      :if={channel.id not in @marks.phantom and channel.id not in @marks.deleted}
                      class="btn btn-ghost btn-xs text-error"
                      phx-click="remove_child"
                      phx-value-type="channel"
                      phx-value-id={channel.id}
                      data-confirm={
                        if @mode == :propose,
                          do: "Propose removing this channel?",
                          else: "Remove this channel?"
                      }
                    >
                      {if @mode == :propose, do: "Propose removal", else: "Remove"}
                    </button>
                  </td>
                </tr>
                <tr :if={package.repo_url}>
                  <td><span class="badge badge-ghost badge-sm">git</span></td>
                  <td class="font-mono text-base-content/60">
                    {String.replace_prefix(package.repo_url, "https://", "")} (implicit)
                  </td>
                  <td class="text-xs text-base-content/70 font-mono">
                    {derived_versions_label(package, "git")}
                  </td>
                  <td class="text-xs text-base-content/60"></td>
                  <td :if={@mode != :view}></td>
                </tr>
              </tbody>
            </table>
            <p :if={package.channels == []} class="text-sm text-base-content/60">No channels yet.</p>
            <p :if={derivation_issues(package) != []} class="text-xs text-warning mt-1">
              ⚠ {Enum.join(derivation_issues(package), " · ")}
            </p>
            <p :if={package.derivation_cached_at} class="text-xs text-base-content/50 mt-1">
              Ranges derived {format_dt(package.derivation_cached_at)} — refresh derivation for
              current data.
            </p>
          </div>

          <div class="mt-2">
            <div class="flex items-center justify-between">
              <h4 class="text-sm font-semibold text-base-content/70">Version boundaries</h4>
              <button
                :if={@mode != :view and package.id not in @marks.phantom}
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
                  <td class="font-mono text-xs" title={event.commit_sha}>
                    {boundary_label(event)}
                  </td>
                  <td class="text-xs">
                    <span
                      :if={event.package_channel_id}
                      class="badge badge-ghost badge-sm font-mono"
                      title="Applies only to this channel"
                    >
                      {scoped_channel_label(package, event)}
                    </span>
                  </td>
                  <td class="text-xs text-base-content/60">{event.note}</td>
                  <td :if={@mode != :view} class="text-right whitespace-nowrap">
                    <button
                      :if={event.id not in @marks.phantom and event.id not in @marks.deleted}
                      class="btn btn-ghost btn-xs"
                      phx-click="edit_child"
                      phx-value-type="event"
                      phx-value-id={event.id}
                    >
                      Edit
                    </button>
                    <span :if={event.id in @marks.phantom} class="badge badge-info badge-xs">proposed</span>
                    <span :if={event.id in @marks.deleted} class="badge badge-error badge-xs">removal proposed</span>
                    <button
                      :if={event.id not in @marks.phantom and event.id not in @marks.deleted}
                      class="btn btn-ghost btn-xs text-error"
                      phx-click="remove_child"
                      phx-value-type="event"
                      phx-value-id={event.id}
                      data-confirm={
                        if @mode == :propose,
                          do: "Propose removing this boundary?",
                          else: "Remove this boundary fact?"
                      }
                    >
                      {if @mode == :propose, do: "Propose removal", else: "Remove"}
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

      <.inline_suggestions
        case_record={@raw_case_record}
        section_id="affected"
        current_user={@current_user}
        can_resolve={@can_resolve}
      />
    </.panel>
    """
  end

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

  slot :row, required: true

  defp rows_section(assigns) do
    assigns = assign(assigns, :sortable, assigns.mode == :edit and assigns.sort_event != nil)

    ~H"""
    <.panel id={@id} title={@heading}>
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
            <div>{render_slot(@row, row)}</div>
            <span :if={row.id in @marks.phantom} class="badge badge-info badge-xs">proposed</span>
            <span :if={row.id in @marks.deleted} class="badge badge-error badge-xs">removal proposed</span>
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
      <p :if={@rows == []} class="text-sm text-base-content/60">None yet.</p>

      <.inline_suggestions
        case_record={@raw_case_record}
        section_id={@id}
        current_user={@current_user}
        can_resolve={@can_resolve}
      />
    </.panel>
    """
  end

  defp reports_section(assigns) do
    ~H"""
    <.panel title={"Reports (#{length(@case_record.vulnerability_reports)})"}>
      <:actions>
        <.link :if={@poc} navigate={~p"/reports"} class="link link-hover text-primary">
          Report triage
        </.link>
      </:actions>

      <div
        :for={report <- Enum.sort_by(@case_record.vulnerability_reports, & &1.inserted_at, DateTime)}
        class="rounded-lg border border-base-300 bg-base-300/30 p-3 text-sm mb-2 last:mb-0"
      >
        <div class="flex items-start justify-between gap-2">
          <span class="font-semibold">{report.summary}</span>
          <span class={["badge badge-sm shrink-0", report_badge_class(report.state)]}>
            {report.state}
          </span>
        </div>

        <p class="text-xs text-base-content/60">
          by {display_name(report.reporter)} · {relative_time(report.inserted_at)}
        </p>

        <p :if={report.triage_notes} class="text-xs text-base-content/70 italic">
          {report.triage_notes}
        </p>

        <details>
          <summary class="cursor-pointer text-xs text-base-content/60">Report payload</summary>
          <pre class="bg-base-300 rounded p-2 text-xs overflow-x-auto max-h-60 mt-1">{pretty_json(report.report_json)}</pre>
        </details>
      </div>
    </.panel>
    """
  end

  defp report_badge_class(:submitted), do: "badge-warning"
  defp report_badge_class(:triaged), do: "badge-info"
  defp report_badge_class(:accepted), do: "badge-success"
  defp report_badge_class(:rejected), do: "badge-error"
  defp report_badge_class(_other), do: "badge-ghost"

  # The User read policy is self-or-POC: a supporter sees the report through
  # their case assignment but not the reporter account behind it.
  # The User read policy allows loads through case-scoped relationships, but
  # field policies hide everything except :name from non-POC viewers - and
  # a forbidden email is an Ash.ForbiddenField struct, not nil.
  defp display_name(%{name: name}) when is_binary(name) and name != "", do: name
  defp display_name(%{email: email}) when is_binary(email), do: email
  defp display_name(_user), do: "(hidden)"

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
          <div class="mt-2 flex items-center gap-4 border-b border-base-300 text-sm">
            <.preview_tab_button tab="validation" active={@preview_tab}>
              Validation
            </.preview_tab_button>
            <.preview_tab_button tab="json" active={@preview_tab}>
              Rendered JSON
            </.preview_tab_button>
            <.preview_tab_button :if={@amendment} tab="diff" active={@preview_tab}>
              Diff to published
            </.preview_tab_button>
            <button
              class="link link-hover ml-auto pb-2 text-xs text-primary"
              phx-click="preview"
              disabled={@preview == :loading}
            >
              {if @preview == :loading, do: "Rendering…", else: "Re-render"}
            </button>
          </div>
        </div>

        <div class="flex-1 overflow-y-auto px-5 py-4">
          <div :if={@preview_tab == "validation"}>
            <p :if={@preview == :loading} class="text-sm text-base-content/60">Rendering…</p>
            <div :if={is_map(@preview)}>
              <ul class="text-[0.79rem]">
                <li
                  :for={row <- validation_rows(@preview)}
                  class="flex items-center gap-2 py-1 text-base-content/70"
                >
                  <span :if={row.ok} class="shrink-0 font-bold text-success">✓</span>
                  <span :if={!row.ok} class="shrink-0 font-bold text-warning">✗</span>
                  <span class="min-w-0">{row.text}</span>
                  <a
                    :if={row.section}
                    href={"##{row.section}"}
                    phx-click="close_preview"
                    class="link link-hover ml-auto shrink-0 text-xs text-primary"
                  >
                    Go to {row.section}
                  </a>
                </li>
              </ul>
              <p :if={is_nil(@preview["validation"])} class="mt-2 text-xs text-base-content/50">
                Record validation (schema, cvelint, hex.pm) runs once a CVE ID is assigned.
              </p>
              <p :if={@preview["overrides_applied"] != []} class="mt-3 text-xs text-base-content/50">
                Overrides applied: {Enum.join(@preview["overrides_applied"], ", ")}
              </p>
            </div>
          </div>

          <div :if={@preview_tab == "json"}>
            <p :if={@preview == :loading} class="text-sm text-base-content/60">Rendering…</p>
            <pre
              :if={is_map(@preview)}
              class="overflow-x-auto rounded-lg border border-base-300 bg-base-100 p-3 font-mono text-xs leading-5"
            >{json_highlight(@preview["cna"])}</pre>
          </div>

          <div :if={@preview_tab == "diff"}>
            <p :if={@diff == :loading} class="text-sm text-base-content/60">Diffing…</p>
            <div :if={is_list(@diff)} class="space-y-2">
              <p :if={not Diff.changed?(@diff)} class="text-sm text-base-content/60">
                No changes against the published record.
              </p>
              <pre
                :if={Diff.changed?(@diff)}
                class="overflow-x-auto rounded-lg border border-base-300 bg-base-100 p-3 text-xs leading-5"
              ><span
        :for={line <- @diff}
        class={["block whitespace-pre", diff_line_class(line)]}
      >{diff_line_text(line)}</span></pre>
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
            publish_blocked={blocker_count(@preview) > 0}
          />
          <span :if={blocker_count(@preview) > 0} class="text-xs text-base-content/50">
            {blocker_note(blocker_count(@preview), @case_record.state)}
          </span>
        </div>
      </aside>
    </div>
    """
  end

  attr :tab, :string, required: true
  attr :active, :string, required: true
  slot :inner_block, required: true

  defp preview_tab_button(assigns) do
    ~H"""
    <button
      class={[
        "pb-2",
        if(@active == @tab,
          do: "font-bold text-base-content [box-shadow:inset_0_-2px_0_var(--color-primary)]",
          else: "text-base-content/60 hover:text-base-content"
        )
      ]}
      phx-click="preview_tab"
      phx-value-tab={@tab}
    >
      {render_slot(@inner_block)}
    </button>
    """
  end

  # One row per validation check (✓ when its validator produced no errors)
  # followed by one row per render blocker; the ✗ rows are what the footer's
  # blocker count refers to.
  @validators [schema: "CVE record schema", cvelint: "cvelint", hex: "Hex packages exist"]

  defp validation_rows(preview) do
    validator_rows(preview["validation"]) ++
      Enum.map(preview["blockers"], fn blocker ->
        %{ok: false, text: blocker, section: blocker_section(blocker)}
      end)
  end

  defp validator_rows(nil), do: []

  defp validator_rows(validation) do
    errors = validation[:errors] || []

    Enum.flat_map(@validators, fn {source, label} ->
      case Enum.filter(errors, &(&1.source == source)) do
        [] ->
          [%{ok: true, text: label, section: nil}]

        failures ->
          Enum.map(failures, &%{ok: false, text: "#{label}: #{&1.message}", section: nil})
      end
    end)
  end

  defp blocker_count(preview), do: Enum.count(validation_rows(preview), &(not &1.ok))

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

  defp resolved_proposal_card(assigns) do
    ~H"""
    <div class="rounded-lg border border-base-300 bg-base-300/30 p-3 text-sm">
      <div class="flex items-center justify-between gap-2">
        <span class="font-semibold truncate">{proposal_summary(@proposal)}</span>
        <span class={["badge badge-sm shrink-0", proposal_badge_class(@proposal.state)]}>
          {@proposal.state}
        </span>
      </div>

      <pre
        :if={@proposal.operation != :set and @proposal.proposed_value}
        class="mt-1 max-h-40 overflow-x-auto rounded bg-base-300 p-2 text-xs"
      >{pretty_json(@proposal.proposed_value["value"])}</pre>

      <div :if={@proposal.reasoning} class="mt-1 text-base-content/80">
        <.markdown content={@proposal.reasoning} class="prose-xs" />
      </div>

      <p class="mt-1 text-xs text-base-content/60">
        by {display_name(@proposal.author)} · {relative_time(@proposal.inserted_at)}
        <span :if={@proposal.resolved_by}>
          · resolved by {display_name(@proposal.resolved_by)}
        </span>
      </p>

      <p :if={@proposal.resolution_note} class="mt-1 text-xs text-base-content/60 italic">
        {@proposal.resolution_note}
      </p>
    </div>
    """
  end

  defp assignments_section(assigns) do
    ~H"""
    <.panel title="People">
      <ul class="space-y-2 text-sm">
        <li
          :for={assignment <- @case_record.assignments}
          class="flex items-center justify-between gap-2"
        >
          <span class="flex min-w-0 items-center gap-2">
            <.avatar_disc user={assignment.user} variant={person_variant(@case_record, assignment)} />
            <span class="truncate">{display_name(assignment.user)}</span>
            <span class="shrink-0 text-base-content/50">{person_role(assignment.user)}</span>
          </span>
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
      <p :if={@case_record.assignments == []} class="text-sm text-base-content/60">
        No one assigned yet.
      </p>

      <form phx-submit="assign_user" class="flex items-center gap-2 mt-2">
        <select name="user_id" required class="select select-bordered select-sm flex-1">
          <option value="">Assign a user…</option>
          <option
            :for={user <- @users}
            :if={not Enum.any?(@case_record.assignments, &(&1.user_id == user.id))}
            value={user.id}
          >
            {display_name(user)}
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
          <.child_fields
            type={@child_form.type}
            form={@child_form.form}
            catalog_options={@catalog_options}
            channel_options={@child_form.channel_options}
          />

          <input
            :if={@mode == :propose}
            type="text"
            name="reasoning"
            placeholder="Reasoning (attached to proposals, optional)"
            class="input input-bordered input-sm w-full mt-2"
          />

          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" phx-click="cancel_child">Cancel</button>
            <button type="submit" class="btn btn-primary btn-sm">
              {if @mode == :propose, do: "Propose", else: "Save"}
            </button>
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
    <.program_files_field form={@form} />
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

  # The preset forms: vendor/product/repo/CPE and channels are prefilled;
  # only the boundary facts and content lists remain.
  defp child_fields(%{type: "package_" <> _preset} = assigns) do
    ~H"""
    <.input
      :if={@type != "package_gleam"}
      field={@form[:applications]}
      type="text"
      value={list_value(@form[:applications])}
      placeholder={if @type == "package_elixir", do: "e.g. elixir, mix", else: "e.g. ssh, stdlib"}
    >
      <:label>Affected applications (comma separated)</:label>
    </.input>
    <.input
      field={@form[:introduced_commit]}
      type="text"
      placeholder="40-char commit SHA"
      class="w-full input font-mono"
    >
      <:label>Introducing commit</:label>
    </.input>
    <.input
      field={@form[:fixed_commits]}
      type="text"
      value={list_value(@form[:fixed_commits])}
      class="w-full input font-mono"
    >
      <:label>Fix commits (comma separated, one per release branch)</:label>
    </.input>
    <.program_files_field form={@form} />
    """
  end

  defp child_fields(%{type: "channel"} = assigns) do
    ~H"""
    <.input field={@form[:purl_type]} type="select" options={enum_options(PackageChannel.PurlType)}>
      <:label>Purl type (the git/forge entry is added automatically)</:label>
    </.input>
    <div class="grid sm:grid-cols-2 gap-x-4">
      <.input field={@form[:namespace]} type="text" placeholder="e.g. gleam.run">
        <:label>Namespace (optional)</:label>
      </.input>
      <.input field={@form[:name]} type="text" placeholder="e.g. my_package">
        <:label>Name (empty for hosted)</:label>
      </.input>
    </div>
    <.input
      type="text"
      name="child[qualifiers]"
      value={qualifiers_value(@form[:qualifiers])}
      placeholder="repository_url=ghcr.io/owner"
    >
      <:label>Qualifiers (key=value, comma separated)</:label>
      <:description>
        Only overrides are stored here — otp channels derive repository_url and
        vcs_url from the package's repository automatically at render time.
      </:description>
    </.input>
    <.input
      field={@form[:subpath]}
      type="text"
      placeholder="e.g. lib/ssh"
      class="w-full input font-mono"
    >
      <:label>Subpath (optional)</:label>
      <:description>
        Repository directory this channel distributes. Program files scope to
        it, paths relative to it — e.g. lib/ssh for pkg:otp/ssh. Empty
        distributes the whole repository.
      </:description>
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
      :if={@form.source.type == :create and @channel_options != []}
      field={@form[:package_channel_id]}
      type="select"
      options={@channel_options}
      prompt="All channels (package-wide)"
    >
      <:label>Channel scope</:label>
      <:description>
        Scoping records an explicit boundary for that channel only — e.g. bounding
        the former application when functionality moved between applications.
      </:description>
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

    <fieldset class="fieldset mb-2">
      <label class="label">Tags</label>
      <%!-- Sentinel so unchecking every box still submits (and clears) tags. --%>
      <input type="hidden" name="child[tags][]" value="" />
      <div class="grid grid-cols-2 gap-x-4 gap-y-1">
        <label
          :for={tag <- CaseReference.standard_tags()}
          class="flex items-center gap-2 text-sm cursor-pointer"
        >
          <input
            type="checkbox"
            name="child[tags][]"
            value={tag}
            checked={tag in selected_tags(@form)}
            class="checkbox checkbox-xs"
          />
          {tag}
        </label>
      </div>
    </fieldset>

    <.input
      type="text"
      name="child[custom_tags]"
      value={custom_tags_value(@form)}
      placeholder="x_version-scheme"
    >
      <:label>Custom tags (x_ prefixed, comma separated)</:label>
    </.input>
    <%!-- No position field: new references append; the list is drag-sortable. --%>
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
    <%!-- No position field: new credits append; the list is drag-sortable. --%>
    """
  end

  defp child_fields(%{type: "weakness"} = assigns) do
    ~H"""
    <.input
      field={@form[:cwe_id]}
      type="text"
      list="cwe-options"
      placeholder="Type a CWE number or name…"
      autocomplete="off"
    >
      <:label>CWE</:label>
    </.input>
    <datalist id="cwe-options">
      <option :for={{id, name} <- @catalog_options.cwe} value={"CWE-#{id} #{name}"}></option>
    </datalist>
    """
  end

  defp child_fields(%{type: "impact"} = assigns) do
    ~H"""
    <.input
      field={@form[:capec_id]}
      type="text"
      list="capec-options"
      placeholder="Type a CAPEC number or name…"
      autocomplete="off"
    >
      <:label>CAPEC</:label>
    </.input>
    <datalist id="capec-options">
      <option :for={{id, name} <- @catalog_options.capec} value={"CAPEC-#{id} #{name}"}></option>
    </datalist>
    """
  end

  defp program_files_field(assigns) do
    ~H"""
    <fieldset class="fieldset mb-2">
      <span class="label mb-1">Program files</span>
      <p class="text-xs text-base-content/60 mb-1">
        Repository-root-relative paths plus the modules and routines each file
        contributes. Channels with a subpath render only the files under it,
        paths relative to it (e.g. lib/ssh/… only on the pkg:otp/ssh channel).
      </p>
      <.inputs_for :let={file_form} field={@form[:program_files]}>
        <div class="rounded-box border border-base-300 p-3 mb-2">
          <div class="flex items-end gap-2">
            <div class="grow">
              <.input
                field={file_form[:path]}
                type="text"
                placeholder="lib/ssh/src/ssh_sftpd.erl"
                class="w-full input input-sm font-mono"
              >
                <:label>Path</:label>
              </.input>
            </div>
            <button
              type="button"
              class="btn btn-ghost btn-xs text-error mb-2"
              phx-click="remove_program_file"
              phx-value-path={file_form.name}
            >
              Remove
            </button>
          </div>
          <div class="grid sm:grid-cols-2 gap-x-4">
            <.input
              field={file_form[:modules]}
              type="text"
              value={list_value(file_form[:modules])}
              placeholder="ssh_sftpd"
              class="w-full input input-sm font-mono"
            >
              <:label>Modules (comma separated)</:label>
            </.input>
            <.input
              field={file_form[:routines]}
              type="text"
              value={list_value(file_form[:routines])}
              placeholder="ssh_sftpd:handle_op/4"
              class="w-full input input-sm font-mono"
            >
              <:label>Routines (comma separated)</:label>
            </.input>
          </div>
        </div>
      </.inputs_for>
      <div>
        <button type="button" class="btn btn-ghost btn-xs" phx-click="add_program_file">
          Add file
        </button>
      </div>
    </fieldset>
    """
  end

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
        Enum.map(
          package.channels,
          &{channel_label(package, &1) || to_string(&1.purl_type), &1.id}
        )
    end
  end

  defp channel_options(_type, _params, _socket), do: []

  defp scoped_channel_label(package, event) do
    case Enum.find(package.channels, &(&1.id == event.package_channel_id)) do
      nil -> "(removed channel)"
      channel -> channel_label(package, channel) || to_string(channel.purl_type)
    end
  end

  # The purl without its qualifier tail — OTP channels carry long
  # repository_url/vcs_url qualifiers that would drown the UI; "?…" hints at
  # the elided rest (the channel table cell's title shows the full purl).
  defp channel_label(package, channel) do
    case Channel.purl_string(package, channel) do
      nil ->
        channel.name

      purl ->
        case String.split(purl, "?", parts: 2) do
          [purl] -> purl
          [base, _qualifiers] -> base <> "?…"
        end
    end
  end

  # Compact per-channel summary of the cached derivation result ("git" is the
  # implicit forge entry). Never authoritative — publish recomputes.
  defp derived_versions_label(package, key) do
    case channel_derivation(package.derivation_cache, key) do
      nil ->
        nil

      derivation ->
        ranges = Enum.map(derivation["versions"] || [], &range_label/1)
        pending = if (derivation["pending"] || []) == [], do: [], else: ["fix unreleased"]

        case ranges ++ pending do
          [] -> "no derived range"
          parts -> Enum.join(parts, " · ")
        end
    end
  end

  defp channel_derivation(nil, _key), do: nil
  defp channel_derivation(cache, "git"), do: cache["git"]
  defp channel_derivation(cache, channel_id), do: get_in(cache, ["channels", channel_id])

  defp range_label(%{"version" => from, "changes" => changes}) when is_list(changes) do
    "≥ #{from}; fixed: #{Enum.map_join(changes, ", ", &shorten(&1["at"]))}"
  end

  defp range_label(%{"version" => from, "lessThan" => "*"}), do: "≥ #{shorten(from)}"

  defp range_label(%{"version" => from, "lessThan" => to}) do
    "≥ #{shorten(from)} < #{shorten(to)}"
  end

  defp range_label(_other), do: "custom"

  defp derivation_issues(%{derivation_cache: nil}), do: []

  defp derivation_issues(%{derivation_cache: cache}) do
    channel_issues =
      cache
      |> Map.get("channels", %{})
      |> Map.values()
      |> Enum.flat_map(&(&1["issues"] || []))

    Enum.uniq((cache["issues"] || []) ++ channel_issues)
  end

  defp boundary_label(%{commit_sha: sha}) when is_binary(sha), do: shorten(sha)
  defp boundary_label(%{version: version}), do: version

  # Full commit SHAs drown the tables; 12 characters identify them fine.
  defp shorten(value) when is_binary(value) do
    if String.match?(value, ~r/^[0-9a-f]{40}$/) do
      String.slice(value, 0, 12) <> "…"
    else
      value
    end
  end

  defp shorten(value), do: value

  # Renders an {:array, :string} form value back into its comma-separated
  # text-input representation.
  defp list_value(field) do
    case field.value do
      values when is_list(values) -> Enum.join(values, ", ")
      value -> value
    end
  end

  # Renders a qualifiers map back into its "key=value, key=value" input form.
  defp qualifiers_value(field) do
    case field.value do
      %{} = qualifiers ->
        Enum.map_join(qualifiers, ", ", fn {key, value} -> "#{key}=#{value}" end)

      value ->
        value
    end
  end

  # The CWE/CAPEC catalogs back the classification datalists; load them once
  # per LiveView, only when a weakness/impact modal first opens.
  defp ensure_catalog_options(socket, type) when type in ["weakness", "impact"] do
    if socket.assigns.catalog_options do
      socket
    else
      weaknesses =
        Varsel.CWE.Weakness
        |> Ash.Query.select([:cwe_id, :name])
        |> Ash.Query.sort(:cwe_id)
        |> Ash.read!(authorize?: false)
        |> Enum.map(&{&1.cwe_id, &1.name})

      attack_patterns =
        Varsel.CAPEC.AttackPattern
        |> Ash.Query.select([:capec_id, :name])
        |> Ash.Query.sort(:capec_id)
        |> Ash.read!(authorize?: false)
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

  defp selected_tags(form), do: List.wrap(form[:tags].value)

  # Custom (x_-prefixed) tags live in their own text input next to the
  # standard-vocabulary checkboxes.
  defp custom_tags_value(form) do
    form
    |> selected_tags()
    |> Enum.filter(&String.starts_with?(&1, "x_"))
    |> Enum.join(", ")
  end
end
