# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AdvisoryComponents do
  @moduledoc """
  The GitHub tab's pieces: the card of the advisory a case is linked to, who
  sees it on GitHub, and the case set against it field by field.
  """
  use VarselWeb, :html

  import VarselWeb.CaseComponents, only: [markdown: 1, suggestion_diff: 1]

  alias Varsel.Cases.GitHubAdvisory.Diff

  @doc """
  Renders the linked advisory: its id, standing, repository and title, when
  it was last read, and the actions the viewer may take on it. `busy` holds
  the actions while a request to GitHub runs. `gh_refresh` offers the read as
  a command for the viewer's own terminal instead.
  """
  attr :link, :map, required: true, doc: "the `Varsel.Cases.GitHubAdvisoryLink`"
  attr :can_refresh, :boolean, default: false
  attr :gh_refresh, :boolean, default: false
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
          :if={@gh_refresh and not @can_refresh}
          type="button"
          phx-click="gh_refresh"
          class="btn btn-xs btn-ghost"
        >
          Refresh with gh
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
  Renders who sees the linked advisory on GitHub, as
  `Varsel.Cases.GitHubAdvisory.Audience` resolved it: the collaborators, each
  team's members and the organization's owners, each marked when they are on
  the case already. With `can_grant`, everyone else offers to be given access.
  `loading` shows the panel while GitHub is asked.
  """
  attr :audience, :map, default: nil, doc: "the resolved `Varsel.Cases.GitHubAdvisory.Audience`"

  attr :on_case, :map,
    default: %{},
    doc: "downcased GitHub login to `:assigned` or `:invited` for everyone on the case"

  attr :can_grant, :boolean, default: false
  attr :loading, :boolean, default: false

  def advisory_audience(assigns) do
    ~H"""
    <.panel id="advisory-audience">
      <:title>Who sees it on GitHub</:title>
      <p :if={@loading} class="text-sm text-base-content/60">Asking GitHub…</p>
      <div :if={!@loading} class="space-y-3 text-sm">
        <.audience_group
          :if={@audience.users != []}
          label="Collaborators"
          logins={@audience.users}
          on_case={@on_case}
          can_grant={@can_grant}
        />
        <.audience_group
          :for={team <- @audience.teams}
          label={"Team #{team.slug}"}
          logins={team.members}
          on_case={@on_case}
          can_grant={@can_grant}
        />
        <.audience_group
          label="Organization owners"
          logins={@audience.owners}
          on_case={@on_case}
          can_grant={@can_grant}
        />
      </div>
    </.panel>
    """
  end

  attr :label, :string, required: true

  attr :logins, :any,
    required: true,
    doc: "the logins, or `:unknown` when the viewer cannot list them"

  attr :on_case, :map, required: true
  attr :can_grant, :boolean, required: true

  defp audience_group(assigns) do
    ~H"""
    <div>
      <p class="text-[0.66rem] font-semibold uppercase tracking-wider text-base-content/50">
        {@label}
      </p>
      <p :if={@logins == :unknown} class="text-base-content/60">
        Not readable with your GitHub account. GitHub lists an organization's people to its
        members.
      </p>
      <p :if={@logins == []} class="text-base-content/60">Nobody.</p>
      <ul :if={is_list(@logins) and @logins != []} class="divide-y divide-base-300">
        <li :for={login <- @logins} class="flex items-center gap-3 py-1" id={"audience-#{login}"}>
          <.link
            href={"https://github.com/#{login}"}
            target="_blank"
            rel="noopener"
            class="link link-hover font-mono text-xs"
          >
            {login}
          </.link>
          <.state :if={@on_case[String.downcase(login)] == :assigned} dot="bg-success" class="text-xs">
            on the case
          </.state>
          <.state :if={@on_case[String.downcase(login)] == :invited} dot="bg-info" class="text-xs">
            invited
          </.state>
          <button
            :if={@can_grant and is_nil(@on_case[String.downcase(login)])}
            type="button"
            phx-click="grant_access"
            phx-value-login={login}
            data-confirm={"Give #{login} access to this case?"}
            class="btn btn-xs btn-ghost ml-auto"
          >
            Give access
          </button>
        </li>
      </ul>
    </div>
    """
  end

  @doc """
  Renders the diff rows of `Varsel.Cases.GitHubAdvisory.Diff` as a table:
  each field with what the case says, what the advisory says, and how the
  two relate. With `can_pull`, a row the advisory can add to offers to pull
  its field, and the panel to pull every such field at once. `can_push`
  offers the same for the rows the case can write to the advisory. `busy`
  holds every pull and push while a request to GitHub runs. `gh_pull` and
  `gh_push` offer a read and pull, or a push, as a command for the viewer's
  own terminal instead.
  """
  attr :rows, :list, required: true
  attr :can_pull, :boolean, default: false
  attr :can_push, :boolean, default: false
  attr :gh_pull, :boolean, default: false
  attr :gh_push, :boolean, default: false
  attr :busy, :boolean, default: false

  def advisory_diff(assigns) do
    assigns =
      assign(assigns,
        rows_with_ids: row_ids(assigns.rows),
        pullable_fields: fields_where(assigns.rows, &Diff.pullable?/1),
        pushable_fields: fields_where(assigns.rows, &Diff.pushable?/1),
        gh_push: assigns.gh_push and not assigns.can_push
      )

    ~H"""
    <.panel id="advisory-diff">
      <:title>Case against advisory</:title>
      <:actions :if={
        ((@can_pull or @gh_pull) and @pullable_fields != []) or
          ((@can_push or @gh_push) and @pushable_fields != [])
      }>
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
          :if={@gh_pull and @pullable_fields != []}
          type="button"
          phx-click="gh_pull"
          phx-value-fields={Enum.join(@pullable_fields, ",")}
          class="btn btn-xs btn-eef-quiet"
        >
          Read again and pull all with gh
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
        <button
          :if={@gh_push and @pushable_fields != []}
          type="button"
          phx-click="gh_push"
          phx-value-fields={Enum.join(@pushable_fields, ",")}
          class="btn btn-xs btn-eef-quiet"
        >
          Push all with gh
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
              <th :if={@can_pull or @can_push or @gh_push} class="w-24"></th>
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
              <td
                :if={@can_pull or @can_push or @gh_push}
                class="align-top whitespace-nowrap text-right"
              >
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
                <button
                  :if={@gh_push and Diff.pushable?(row)}
                  type="button"
                  phx-click="gh_push"
                  phx-value-fields={row.field}
                  class="btn btn-xs btn-ghost"
                >
                  Push with gh
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

  @doc """
  Renders the command of a `Varsel.Cases.GitHubManualRequest` in a modal: one
  shell pipeline that fetches the request, sends it to GitHub with `gh api`,
  and posts GitHub's answer back to `base_url`. `token` is the request's
  one-time token, which the command carries and the page shows nowhere else.
  """
  attr :request, :map,
    required: true,
    doc: "the request: `id`, `operation`, `method`, `path`, `owner`, `repo`, `ghsa_id` and `fields`"

  attr :token, :string, required: true
  attr :base_url, :string, required: true

  def gh_command_modal(assigns) do
    assigns =
      assign(assigns, command: gh_command(assigns.request, assigns.token, assigns.base_url))

    ~H"""
    <.modal id="gh-command" title="Do it with gh" on_cancel="close_gh" class="max-w-3xl">
      <div class="space-y-3 text-sm">
        <p>
          Run this in a terminal where <code class="font-mono">gh</code>
          is signed in to your GitHub account. It {gh_summary(@request)} as you, then sends
          GitHub's answer back here.
        </p>
        <div id="gh-command-text">
          <.code_block source={@command} language="bash" />
        </div>
        <p class="text-base-content/60">
          The command is valid for 15 minutes and works once. This page updates when GitHub's
          answer arrives.
        </p>
      </div>
      <:actions>
        <button type="button" phx-click="close_gh" class="btn btn-sm btn-ghost">Close</button>
      </:actions>
    </.modal>
    """
  end

  @doc """
  The shell command of a manual GitHub request. A read has no body, so it
  starts at `gh api`.
  """
  @spec gh_command(map(), String.t(), String.t()) :: String.t()
  def gh_command(request, token, base_url) do
    endpoint = "#{base_url}/api/github/manual/#{request.id}"
    auth = ~s(-H "Authorization: Bearer #{token}")

    result =
      ~s(curl -sS --fail-with-body #{auth} -H "Content-Type: application/json" #{endpoint}/result --data-binary @-)

    case request.method do
      :get ->
        "gh api #{request.path} \\\n  | #{result}"

      method ->
        "curl -sf #{auth} #{endpoint}/request \\\n" <>
          "  | gh api -X #{method |> Atom.to_string() |> String.upcase()} #{request.path} --input - \\\n" <>
          "  | #{result}"
    end
  end

  defp gh_summary(%{operation: :read, advisory_url: url, case_id: nil, ghsa_id: ghsa_id}) when is_binary(url),
    do: "reads #{ghsa_id} from GitHub and opens a case from it"

  defp gh_summary(%{operation: :read, advisory_url: url, ghsa_id: ghsa_id}) when is_binary(url),
    do: "reads #{ghsa_id} from GitHub and links it to the case"

  defp gh_summary(%{operation: :read, fields: [_field | _rest] = fields, ghsa_id: ghsa_id}),
    do: "reads #{ghsa_id} again and pulls #{Enum.map_join(fields, ", ", &field_label/1)} onto the case"

  defp gh_summary(%{operation: :read, ghsa_id: ghsa_id}), do: "reads #{ghsa_id} again"

  defp gh_summary(%{operation: :push, fields: fields, ghsa_id: ghsa_id}),
    do: "writes #{Enum.map_join(fields, ", ", &field_label/1)} to #{ghsa_id}"

  defp gh_summary(%{operation: :report, path: path, owner: owner, repo: repo}) do
    if String.ends_with?(path, "/reports"),
      do: "reports the case privately to the maintainers of #{owner}/#{repo}",
      else: "opens a draft advisory of the case on #{owner}/#{repo}"
  end

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
