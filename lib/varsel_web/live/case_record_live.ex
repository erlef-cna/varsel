# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseRecordLive do
  @moduledoc """
  The rendered side of a case: the CVE tab, the OSV tab, and the Publication
  tab that validates the record and publishes it.

  Each tab shows the record as it renders now, rendered once on mount and
  again on request. A case with a published record also offers a diff
  against it.
  """
  use VarselWeb, :live_view

  import VarselWeb.CaseComponents, only: [case_header: 1, validation_checklist: 1]

  alias Varsel.Cases
  alias Varsel.Cases.Case.Calculations.Preview.Diff
  alias VarselWeb.CaseLifecycle

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    socket =
      socket
      |> assign(
        preview: :loading,
        validation: nil,
        record_views: %{cve: "record", osv: "record"},
        diffs: %{}
      )
      |> CaseLifecycle.mount(id, load: [:cve_id, :cve_record], after_fetch: &after_fetch/2)
      |> render_preview()

    {:ok, socket}
  end

  defp after_fetch(case_record, socket) do
    assign(socket, page_title: case_record.title || "Case")
  end

  @impl Phoenix.LiveView
  def handle_params(_params, _uri, socket), do: {:noreply, socket}

  @impl Phoenix.LiveView
  def handle_event("render", _params, socket) do
    {:noreply, render_preview(socket)}
  end

  def handle_event("record_view", %{"view" => view}, socket) when view in ["record", "diff"] do
    tab = socket.assigns.live_action
    socket = assign(socket, record_views: Map.put(socket.assigns.record_views, tab, view))

    # A diff (against what is published) is computed lazily the first time it
    # is shown.
    socket =
      if view == "diff" and not Map.has_key?(socket.assigns.diffs, tab) do
        start_diff(socket, tab)
      else
        socket
      end

    {:noreply, socket}
  end

  # Publishing refreshes derivations (git fetches); run it off the LiveView.
  def handle_event("lifecycle", %{"action" => "publish"}, socket) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    {:noreply,
     socket
     |> put_flash(:info, "Publishing — rendering and validating the record…")
     |> start_async(:publish, fn -> Cases.publish_case(case_record, actor: actor) end)}
  end

  @impl Phoenix.LiveView
  def handle_async(:preview, {:ok, case_record}, socket) do
    {:noreply, assign(socket, preview: case_record.preview, validation: case_record.validation)}
  end

  def handle_async(:preview, {:exit, reason}, socket) do
    {:noreply,
     socket
     |> assign(preview: nil, validation: nil)
     |> put_flash(:error, "Rendering failed: #{Exception.format_exit(reason)}")}
  end

  def handle_async(:publish, {:ok, result}, socket) do
    socket =
      case result do
        {:ok, _case_record} -> put_flash(socket, :info, "Publish handed to MITRE.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_async(:publish, {:exit, reason}, socket) do
    {:noreply, put_flash(socket, :error, "Publish failed: #{Exception.format_exit(reason)}")}
  end

  def handle_async({:diff, tab}, {:ok, lines}, socket) do
    {:noreply, assign(socket, diffs: Map.put(socket.assigns.diffs, tab, lines))}
  end

  def handle_async({:diff, tab}, {:exit, reason}, socket) do
    {:noreply,
     socket
     |> assign(diffs: Map.delete(socket.assigns.diffs, tab))
     |> put_flash(:error, "Diff failed: #{Exception.format_exit(reason)}")}
  end

  ## ----------------------------------------------------------------- helpers

  # The static render has no case to render yet when the mount redirected.
  defp render_preview(%{assigns: %{case_record: %{} = case_record}} = socket) do
    actor = socket.assigns.current_user

    if connected?(socket) do
      socket
      |> assign(preview: :loading, diffs: %{})
      |> start_async(:preview, fn ->
        Cases.get_case!(case_record.id, load: [:preview, :validation], actor: actor)
      end)
    else
      socket
    end
  end

  defp render_preview(socket), do: socket

  defp start_diff(socket, tab) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    socket
    |> assign(diffs: Map.put(socket.assigns.diffs, tab, :loading))
    |> start_async({:diff, tab}, fn ->
      # Both sides come from calculations loaded under the actor, so the diff is
      # as authorized as the page load.
      case_record =
        Cases.get_case!(case_record.id,
          load: [:preview, :published_cna, :published_osv],
          actor: actor
        )

      case tab do
        :cve ->
          Diff.lines(
            case_record.published_cna || %{},
            get_in(case_record.preview.cve_record, ["containers", "cna"])
          )

        :osv ->
          Diff.lines(case_record.published_osv || %{}, case_record.preview.osv_record || %{})
      end
    end)
  end

  # An amendment: the backing CVE record already carries a published CNA
  # container, so publishing pushes an update and a diff against it is
  # meaningful.
  defp amendment?(case_record) do
    match?(%{cve_record: %{cve_json: %{"containers" => %{"cna" => %{}}}}}, case_record)
  end

  # The +/- prefixes make the joined text valid diff syntax, so the
  # code_block's Lumis "diff" grammar colors the lines.
  defp diff_line_text({:del, line}), do: "- " <> line
  defp diff_line_text({:ins, line}), do: "+ " <> line
  defp diff_line_text({:eq, line}), do: "  " <> line
  defp diff_line_text({:skip, count}), do: "  ⋯ #{count} unchanged lines"

  # Jason, not the stdlib JSON module: only Jason has a pretty printer.
  defp pretty_json(value), do: Jason.encode!(value, pretty: true)

  ## ------------------------------------------------------------------ render

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

      <.page_container>
        <.record_pane
          :if={@live_action == :cve}
          tab={:cve}
          loading={@preview == :loading}
          record={if(is_map(@preview), do: @preview.cve_record)}
          amendment={amendment?(@case_record)}
          view={@record_views.cve}
          diff={@diffs[:cve]}
        />

        <.record_pane
          :if={@live_action == :osv}
          tab={:osv}
          loading={@preview == :loading}
          record={if(is_map(@preview), do: @preview.osv_record)}
          amendment={amendment?(@case_record)}
          view={@record_views.osv}
          diff={@diffs[:osv]}
        >
          <p :if={is_map(@preview)} class="text-sm text-base-content/60">
            No OSV record: {@preview.osv_status}
          </p>
        </.record_pane>

        <.publication_pane
          :if={@live_action == :publication}
          case_record={@case_record}
          current_user={@current_user}
          preview={@preview}
          validation={@validation}
        />
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

  attr :loading, :boolean, required: true

  defp render_link(assigns) do
    ~H"""
    <button class="link link-hover text-xs text-primary" phx-click="render" disabled={@loading}>
      {if @loading, do: "Rendering…", else: "Re-render"}
    </button>
    """
  end

  attr :tab, :atom, required: true
  attr :loading, :boolean, required: true
  attr :record, :map, required: true, doc: "the rendered document, nil while absent"
  attr :amendment, :boolean, required: true
  attr :view, :string, required: true
  attr :diff, :any, required: true, doc: "nil until requested, :loading, or the diff lines"
  slot :inner_block, doc: "shown instead of the document when there is none"

  defp record_pane(assigns) do
    ~H"""
    <div class="space-y-3">
      <div class="flex items-center justify-between gap-3">
        <div :if={@amendment} class="join">
          <button
            :for={{view, label} <- [{"record", "Record"}, {"diff", "Diff to published"}]}
            type="button"
            class={[
              "join-item btn btn-xs",
              if(@view == view,
                do: "btn-primary",
                else: "bg-base-200 text-base-content/80 border-base-300 hover:bg-base-300"
              )
            ]}
            phx-click="record_view"
            phx-value-view={view}
          >
            {label}
          </button>
        </div>
        <div class="ml-auto"><.render_link loading={@loading} /></div>
      </div>

      <div :if={@view == "record"}>
        <p :if={@loading} class="text-sm text-base-content/60">Rendering…</p>
        <.code_block :if={@record} source={pretty_json(@record)} />
        <%= if not @loading and is_nil(@record) do %>
          {render_slot(@inner_block)}
        <% end %>
      </div>

      <div :if={@view == "diff"}>
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
    """
  end

  attr :case_record, :map, required: true
  attr :current_user, :map, required: true
  attr :preview, :any, required: true
  attr :validation, :any, required: true

  defp publication_pane(assigns) do
    ~H"""
    <div class="space-y-4">
      <.panel>
        <:title>Validation</:title>
        <:actions><.render_link loading={@preview == :loading} /></:actions>
        <p :if={@preview == :loading} class="text-sm text-base-content/60">Rendering…</p>
        <div :if={is_map(@preview)}>
          <.validation_checklist rows={validation_rows(@preview, @validation)}>
            <:jump :let={row}>
              <.link
                navigate={~p"/cases/#{@case_record.id}" <> "#" <> row.section}
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
      </.panel>

      <div :if={is_map(@preview)} class="flex flex-wrap items-center gap-3">
        <button
          :if={Cases.can_publish_case?(@current_user, @case_record, validate?: true)}
          class={["btn btn-sm btn-eef", blocker_count(@preview, @validation) > 0 && "opacity-45"]}
          disabled={blocker_count(@preview, @validation) > 0}
          phx-click="lifecycle"
          phx-value-action="publish"
          data-confirm="Publish this case?"
        >
          Publish
        </button>
        <span :if={blocker_count(@preview, @validation) > 0} class="text-xs text-base-content/50">
          {blocker_note(blocker_count(@preview, @validation), @case_record.state)}
        </span>
      </div>
    </div>
    """
  end

  # One row per validation check (✓ when its validator produced no errors)
  # followed by one row per render blocker; the ✗ rows are what the
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

  # The workspace section a validation finding's code points at: cvelint
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
end
