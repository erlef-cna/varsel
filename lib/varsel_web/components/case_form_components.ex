# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseFormComponents do
  @moduledoc """
  The fields for each of a case's child rows — an affected package and its
  presets, a distribution channel, a version boundary, a reference, a credit,
  a CWE or CAPEC classification.

  Each takes an `AshPhoenix.Form` over its own resource and nothing else, so
  the page wraps them in whatever submits: the shared modal for most, the
  package's own card for the fields it edits in place.
  """
  use Phoenix.Component

  import VarselWeb.CoreComponents

  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseReference
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.VersionEvent

  @doc """
  Renders the line every child form grows while suggesting: why the change is
  being proposed, carried onto the suggestion for whoever reviews it.
  """
  attr :propose?, :boolean, required: true

  def propose_form_fields(assigns) do
    ~H"""
    <input
      :if={@propose?}
      type="text"
      name="reasoning"
      placeholder="Reasoning (attached to the suggestion, optional)"
      class="input input-bordered input-sm w-full mt-2"
    />
    """
  end

  @doc """
  Renders the form for an affected package: who ships it, where it lives,
  and which of its files carry the vulnerability.
  """
  attr :form, :any, required: true, doc: "an AshPhoenix.Form over the resource"
  attr :propose?, :boolean, default: false, doc: "commit as a suggestion rather than a change"
  attr :rest, :global, include: ~w(id), doc: "the form element's id and phx- bindings"
  slot :actions, doc: "the row that submits or abandons the form"

  def affected_package_form(assigns) do
    ~H"""
    <.form for={@form} {@rest}>
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
      <.input field={@form[:include_prereleases]} type="checkbox">
        <:label>Include pre-release versions (rc/alpha/beta) in the affected ranges</:label>
      </.input>
      <.propose_form_fields propose?={@propose?} />
      {render_slot(@actions)}
    </.form>
    """
  end

  # The preset forms: vendor/product/repo/CPE and channels are prefilled;
  # only the boundary facts and content lists remain.
  @doc """
  Renders the form for a package added from a preset — Erlang/OTP, Elixir or
  Gleam. Vendor, product, repository and channels come with the preset, so only
  the boundary facts and the affected files are asked for.
  """
  attr :form, :any, required: true, doc: "an AshPhoenix.Form over the resource"
  attr :propose?, :boolean, default: false, doc: "commit as a suggestion rather than a change"
  attr :preset, :atom, required: true, values: [:otp, :elixir, :gleam]
  attr :rest, :global, include: ~w(id), doc: "the form element's id and phx- bindings"
  slot :actions, doc: "the row that submits or abandons the form"

  def preset_package_form(assigns) do
    ~H"""
    <.form for={@form} {@rest}>
      <.input
        :if={@preset != :gleam}
        field={@form[:applications]}
        type="text"
        value={list_value(@form[:applications])}
        placeholder={if @preset == :elixir, do: "e.g. elixir, mix", else: "e.g. ssh, stdlib"}
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
      <.propose_form_fields propose?={@propose?} />
      {render_slot(@actions)}
    </.form>
    """
  end

  @doc """
  Renders the form for a distribution channel: the purl that names the package
  on one registry, and the part of the repository it ships.
  """
  attr :form, :any, required: true, doc: "an AshPhoenix.Form over the resource"
  attr :propose?, :boolean, default: false, doc: "commit as a suggestion rather than a change"
  attr :rest, :global, include: ~w(id), doc: "the form element's id and phx- bindings"
  slot :actions, doc: "the row that submits or abandons the form"

  def channel_form(assigns) do
    ~H"""
    <.form for={@form} {@rest}>
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
      <.propose_form_fields propose?={@propose?} />
      {render_slot(@actions)}
    </.form>
    """
  end

  @doc """
  Renders the form for a version boundary: the commit or version where the
  vulnerability was introduced or fixed.
  """
  attr :form, :any, required: true, doc: "an AshPhoenix.Form over the resource"
  attr :propose?, :boolean, default: false, doc: "commit as a suggestion rather than a change"
  attr :channel_options, :list, default: [], doc: "channels the boundary can be scoped to"
  attr :rest, :global, include: ~w(id), doc: "the form element's id and phx- bindings"
  slot :actions, doc: "the row that submits or abandons the form"

  def version_event_form(assigns) do
    ~H"""
    <.form for={@form} {@rest}>
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
      <.propose_form_fields propose?={@propose?} />
      {render_slot(@actions)}
    </.form>
    """
  end

  @doc """
  Renders the form for a reference: a URL and what it is — an advisory, a
  patch, a report.
  """
  attr :form, :any, required: true, doc: "an AshPhoenix.Form over the resource"
  attr :propose?, :boolean, default: false, doc: "commit as a suggestion rather than a change"
  attr :rest, :global, include: ~w(id), doc: "the form element's id and phx- bindings"
  slot :actions, doc: "the row that submits or abandons the form"

  def reference_form(assigns) do
    ~H"""
    <.form for={@form} {@rest}>
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
      <.propose_form_fields propose?={@propose?} />
      {render_slot(@actions)}
    </.form>
    """
  end

  @doc """
  Renders the form for a credit: who contributed, and how.
  """
  attr :form, :any, required: true, doc: "an AshPhoenix.Form over the resource"
  attr :propose?, :boolean, default: false, doc: "commit as a suggestion rather than a change"
  attr :rest, :global, include: ~w(id), doc: "the form element's id and phx- bindings"
  slot :actions, doc: "the row that submits or abandons the form"

  def credit_form(assigns) do
    ~H"""
    <.form for={@form} {@rest}>
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
      <.propose_form_fields propose?={@propose?} />
      {render_slot(@actions)}
    </.form>
    """
  end

  @doc """
  Renders the form for a CWE classification, picked from the catalog.
  """
  attr :form, :any, required: true, doc: "an AshPhoenix.Form over the resource"
  attr :propose?, :boolean, default: false, doc: "commit as a suggestion rather than a change"
  attr :catalog_options, :any, required: true, doc: "%{cwe: [{id, name}]} for the picker"
  attr :rest, :global, include: ~w(id), doc: "the form element's id and phx- bindings"
  slot :actions, doc: "the row that submits or abandons the form"

  def weakness_form(assigns) do
    ~H"""
    <.form for={@form} {@rest}>
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
      <.propose_form_fields propose?={@propose?} />
      {render_slot(@actions)}
    </.form>
    """
  end

  @doc """
  Renders the form for a CAPEC classification, picked from the catalog.
  """
  attr :form, :any, required: true, doc: "an AshPhoenix.Form over the resource"
  attr :propose?, :boolean, default: false, doc: "commit as a suggestion rather than a change"
  attr :catalog_options, :any, required: true, doc: "%{capec: [{id, name}]} for the picker"
  attr :rest, :global, include: ~w(id), doc: "the form element's id and phx- bindings"
  slot :actions, doc: "the row that submits or abandons the form"

  def impact_form(assigns) do
    ~H"""
    <.form for={@form} {@rest}>
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
      <.propose_form_fields propose?={@propose?} />
      {render_slot(@actions)}
    </.form>
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

  defp enum_options(enum) do
    Enum.map(enum.values(), &{&1 |> to_string() |> String.replace("_", " "), &1})
  end

  # An {:array, :string} attribute is edited as one comma-separated line.
  defp list_value(field) do
    case field.value do
      values when is_list(values) -> Enum.join(values, ", ")
      value -> value
    end
  end

  # A purl's qualifiers are a map, edited as `key=value` pairs on one line.
  defp qualifiers_value(field) do
    case field.value do
      %{} = qualifiers ->
        Enum.map_join(qualifiers, ", ", fn {key, value} -> "#{key}=#{value}" end)

      value ->
        value
    end
  end

  defp selected_tags(form), do: List.wrap(form[:tags].value)

  # Custom (x_-prefixed) tags live in their own text input beside the
  # standard-vocabulary checkboxes.
  defp custom_tags_value(form) do
    form
    |> selected_tags()
    |> Enum.filter(&String.starts_with?(&1, "x_"))
    |> Enum.join(", ")
  end
end
