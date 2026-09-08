# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AdvisoryComponents do
  @moduledoc """
  The GitHub tab's pieces: the card of the advisory a case is linked to, and
  the case set against it field by field.
  """
  use VarselWeb, :html

  import VarselWeb.CaseComponents, only: [markdown: 1, suggestion_diff: 1]

  alias Varsel.Cases.GitHubAdvisory.Diff

  @doc """
  Renders the linked advisory: its id, standing, repository and title, when
  it was last read, and the actions the viewer may take on it. `busy` holds
  the actions while a request to GitHub runs.
  """
  attr :link, :map, required: true, doc: "the `Varsel.Cases.GitHubAdvisoryLink`"
  attr :can_refresh, :boolean, default: false
  attr :can_unlink, :boolean, default: false
  attr :busy, :boolean, default: false

  def advisory_card(assigns) do
    ~H"""
    <.panel id="github-advisory">
      <:title>Linked advisory</:title>
      <:actions>
        <button
          :if={@can_refresh}
          type="button"
          phx-click="refresh_advisory"
          class="btn btn-xs btn-ghost"
          disabled={@busy}
        >
          Refresh
        </button>
        <button
          :if={@can_unlink}
          type="button"
          phx-click="unlink_advisory"
          data-confirm="Unlink this advisory from the case? Its reference leaves the record with it."
          class="btn btn-xs btn-ghost"
          disabled={@busy}
        >
          Unlink
        </button>
      </:actions>

      <div class="flex flex-wrap items-center gap-3">
        <.link
          href={to_string(@link.html_url)}
          target="_blank"
          rel="noopener"
          class="link link-hover font-mono text-sm"
        >
          {@link.ghsa_id}
        </.link>
        <.advisory_state state={@link.state} />
        <.mono_chip :if={@link.cve_id} size={:small}>{@link.cve_id}</.mono_chip>
        <span :if={@link.owner} class="text-sm text-base-content/60">{@link.owner}/{@link.repo}</span>
      </div>
      <p :if={@link.title} class="mt-2 font-semibold">{@link.title}</p>
      <p class="mt-2 text-xs text-base-content/60">
        Read {format_datetime(@link.fetched_at)}<span :if={@busy}> · asking GitHub…</span>
      </p>
    </.panel>
    """
  end

  attr :state, :atom, required: true

  defp advisory_state(assigns) do
    ~H"""
    <.state dot={state_dot(@state)} class="text-sm">{state_label(@state)}</.state>
    """
  end

  defp state_dot(:published), do: "bg-success"
  defp state_dot(state) when state in [:draft, :triage], do: "bg-warning"
  defp state_dot(_closed_withdrawn_unknown), do: "bg-base-content/40"

  defp state_label(:unknown), do: "unknown state"
  defp state_label(state), do: to_string(state)

  @doc """
  Renders the diff rows of `Varsel.Cases.GitHubAdvisory.Diff` as a table:
  each field with what the case says, what the advisory says, and how the
  two relate. With `can_pull`, a row the advisory can add to offers to pull
  its field, and the panel to pull every such field at once. `can_push`
  offers the same for the rows the case can write to the advisory. `busy`
  holds every pull and push while a request to GitHub runs.
  """
  attr :rows, :list, required: true
  attr :can_pull, :boolean, default: false
  attr :can_push, :boolean, default: false
  attr :busy, :boolean, default: false

  def advisory_diff(assigns) do
    assigns =
      assign(assigns,
        rows_with_ids: row_ids(assigns.rows),
        pullable_fields: fields_where(assigns.rows, &Diff.pullable?/1),
        pushable_fields: fields_where(assigns.rows, &Diff.pushable?/1)
      )

    ~H"""
    <.panel id="advisory-diff">
      <:title>Case against advisory</:title>
      <:actions :if={(@can_pull and @pullable_fields != []) or (@can_push and @pushable_fields != [])}>
        <button
          :if={@can_pull and @pullable_fields != []}
          type="button"
          phx-click="pull_advisory"
          phx-value-fields={Enum.join(@pullable_fields, ",")}
          class="btn btn-xs btn-eef-quiet"
          disabled={@busy}
        >
          Pull all
        </button>
        <button
          :if={@can_push and @pushable_fields != []}
          type="button"
          phx-click="push_advisory"
          phx-value-fields={Enum.join(@pushable_fields, ",")}
          data-confirm="Write these fields to the advisory on GitHub as you?"
          class="btn btn-xs btn-eef-quiet"
          disabled={@busy}
        >
          Push all
        </button>
      </:actions>
      <div class="overflow-x-auto">
        <table class="table table-sm table-fixed w-full">
          <thead>
            <tr>
              <th class="w-40">Field</th>
              <th>Case</th>
              <th>GitHub</th>
              <th class="w-28"></th>
              <th :if={@can_pull or @can_push} class="w-24"></th>
            </tr>
          </thead>
          <tbody>
            <tr :for={{row_id, row} <- @rows_with_ids} id={row_id}>
              <td class="font-medium align-top">{row_label(row)}</td>
              <td :if={row.field == :description} colspan="2" class="align-top">
                <.description_diff row={row} />
              </td>
              <td :if={row.field != :description} class="align-top">
                <.diff_value row={row} side={:ours} />
              </td>
              <td :if={row.field != :description} class="align-top">
                <.diff_value row={row} side={:theirs} />
              </td>
              <td class="align-top whitespace-nowrap"><.diff_status status={row.status} /></td>
              <td :if={@can_pull or @can_push} class="align-top whitespace-nowrap text-right">
                <button
                  :if={@can_pull and Diff.pullable?(row)}
                  type="button"
                  phx-click="pull_advisory"
                  phx-value-fields={row.field}
                  class="btn btn-xs btn-ghost"
                  disabled={@busy}
                >
                  Pull
                </button>
                <button
                  :if={@can_push and Diff.pushable?(row)}
                  type="button"
                  phx-click="push_advisory"
                  phx-value-fields={row.field}
                  data-confirm="Write this field to the advisory on GitHub as you?"
                  class="btn btn-xs btn-ghost"
                  disabled={@busy}
                >
                  Push
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </.panel>
    """
  end

  defp fields_where(rows, pred), do: rows |> Enum.filter(pred) |> Enum.map(& &1.field) |> Enum.uniq()

  # Two packages can share a name, so an affected row is numbered.
  defp row_ids(rows) do
    rows
    |> Enum.map_reduce(0, fn
      %{field: :affected} = row, n -> {{"diff-affected-#{n}", row}, n + 1}
      %{field: field} = row, n -> {{"diff-#{field}", row}, n}
    end)
    |> elem(0)
  end

  # A push replaces the advisory's text with the case's, so the advisory's is
  # the old side of the word diff.
  attr :row, :map, required: true

  defp description_diff(%{row: %{status: :differs}} = assigns) do
    ~H"""
    <.suggestion_diff old={@row.theirs} new={@row.ours} />
    """
  end

  defp description_diff(assigns) do
    assigns = assign(assigns, :text, assigns.row.ours || assigns.row.theirs)

    ~H"""
    <span :if={is_nil(@text)} class="text-base-content/40">—</span>
    <.markdown :if={@text} content={@text} />
    """
  end

  attr :status, :atom, required: true

  defp diff_status(assigns) do
    ~H"""
    <.state dot={status_dot(@status)} class="text-xs">{status_label(@status)}</.state>
    """
  end

  defp status_dot(:same), do: "bg-success"
  defp status_dot(:differs), do: "bg-warning"
  defp status_dot(status) when status in [:ours_only, :theirs_only], do: "bg-info"
  defp status_dot(:not_derived), do: "bg-base-content/40"

  defp status_label(:same), do: "same"
  defp status_label(:differs), do: "differs"
  defp status_label(:ours_only), do: "case only"
  defp status_label(:theirs_only), do: "GitHub only"
  defp status_label(:not_derived), do: "not derived"

  attr :row, :map, required: true
  attr :side, :atom, required: true, values: [:ours, :theirs]

  defp diff_value(assigns) do
    assigns = assign(assigns, :value, Map.fetch!(assigns.row, assigns.side))

    ~H"""
    <%= case {@row.field, @value} do %>
      <% {_field, nil} -> %>
        <span class="text-base-content/40">—</span>
      <% {field, value} when field in [:cve_id, :cvss_v4] -> %>
        <.mono_chip size={:small} class="break-all">{value}</.mono_chip>
      <% {:weaknesses, cwe_ids} -> %>
        <span class="flex flex-wrap gap-1">
          <.mono_chip :for={cwe_id <- cwe_ids} size={:small}>CWE-{cwe_id}</.mono_chip>
        </span>
      <% {:credits, people} -> %>
        <ul class="text-sm">
          <li :for={person <- people}>
            {person.name}<span :if={shows_login?(person)} class="text-base-content/60"> ({person.login})</span>
            <span class="text-base-content/60">
              · {Enum.map_join(person.roles, ", ", &String.replace(to_string(&1), "_", " "))}
            </span>
            <span :if={is_nil(person.login)} class="text-xs text-base-content/50">
              (no GitHub account)
            </span>
          </li>
        </ul>
      <% {:affected, %{ranges: ranges, patched: patched}} -> %>
        <div class="text-sm">
          <p :if={ranges == []} class="text-base-content/40">no ranges</p>
          <p :for={range <- ranges} class="font-mono text-xs">{range}</p>
          <p :if={patched != []} class="text-xs text-base-content/60">
            fixed in {Enum.join(patched, ", ")}
          </p>
        </div>
      <% {_field, text} -> %>
        <span class="text-sm">{text}</span>
    <% end %>
    """
  end

  defp shows_login?(%{login: login, name: name}) when is_binary(login) and is_binary(name),
    do: login != String.downcase(name)

  defp shows_login?(_person), do: false

  defp row_label(%{field: :affected, package: package}), do: "Affected · #{package}"
  defp row_label(%{field: field}), do: field_label(field)

  @doc "The label of a diff field, by its name as the pull and push events carry it."
  @spec field_label(atom() | String.t()) :: String.t()
  def field_label(field) when is_atom(field), do: field |> Atom.to_string() |> field_label()
  def field_label("title"), do: "Title"
  def field_label("description"), do: "Description"
  def field_label("cve_id"), do: "CVE ID"
  def field_label("cvss_v4"), do: "CVSS v4"
  def field_label("weaknesses"), do: "CWEs"
  def field_label("credits"), do: "Credits"
  def field_label("affected"), do: "Affected packages"
end
