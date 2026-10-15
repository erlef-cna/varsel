# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseGitHubLive do
  @moduledoc """
  The GitHub tab of a case: the security advisory it is linked to, read as
  the person looking, who sees it on GitHub, and the case set against it
  field by field. A case without an advisory reports itself to a
  repository's maintainers from here.

  What the viewer can do on the advisory's repository
  (`Varsel.GitHub.Credentials.reach/3`) is asked once per repository, off
  the render path, and decides whether Refresh and Push are offered. Where
  the App is not installed, a POC is offered each request as a `gh` command
  for their own terminal (`Varsel.Cases.GitHubManualRequest`). The command's
  answer writes the link, whose notification reloads the page.
  """
  use VarselWeb, :live_view

  import VarselWeb.AdvisoryComponents
  import VarselWeb.CaseComponents, only: [case_header: 1]

  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisory.Audience
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.Cases.GitHubAdvisory.ReportTargets
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.GitHub.Credentials
  alias Varsel.GitHub.UserToken
  alias VarselWeb.CaseLifecycle

  require Logger

  @github_requests ["refresh_advisory", "push_advisory", "report_to_github"]

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    actor = socket.assigns.current_user

    socket =
      socket
      |> assign(
        busy?: false,
        github_identity?: UserToken.linked?(actor),
        may_try?: Credentials.may_try?(actor),
        reach: nil,
        reach_for: nil,
        audience: nil,
        audience_for: nil,
        report_targets: [],
        report_targets_for: nil,
        repository: nil,
        report_target: nil,
        gh: nil,
        gh_link?: false,
        gh_kind: "draft",
        gh_offers: %{refresh: false, pull: false, push: false, report: false}
      )
      |> CaseLifecycle.mount(id,
        load: [
          :cve_id,
          :cve_record,
          :preview,
          affected_packages: [],
          assignments: [user: [:github_username]],
          invites: [],
          github_advisory_link: [:diff]
        ],
        after_fetch: &after_fetch/2
      )

    {:ok, socket}
  end

  defp after_fetch(case_record, socket) do
    actor = socket.assigns.current_user
    link = case_record.github_advisory_link

    socket
    |> assign(page_title: case_record.title || "Case", link: link, on_case: on_case(case_record))
    |> assign(permissions(actor, case_record, link))
    |> assign_form(link)
    |> assign_report_form(case_record, link)
    |> resolve_audience(link)
    |> check_reach(link)
    |> check_report_targets(case_record)
    |> assign_gh_offers()
    |> check_gh_answer()
  end

  defp assign_gh_offers(socket) do
    %{current_user: actor, link: link, reach: reach, report_targets: targets} = socket.assigns

    offers =
      case {link, reach} do
        {%GitHubAdvisoryLink{}, :not_installed} ->
          %{
            refresh: Cases.can_prepare_manual_refresh?(actor, link.id),
            pull: Cases.can_prepare_manual_pull?(actor, link.id, [:title]),
            push: Cases.can_prepare_manual_push?(actor, link.id, [:title]),
            report: false
          }

        {nil, _reach} ->
          %{
            refresh: false,
            pull: false,
            push: false,
            report: gh_report?(actor, socket.assigns.case_record, targets)
          }

        _installed ->
          %{refresh: false, pull: false, push: false, report: false}
      end

    assign(socket, gh_offers: offers)
  end

  defp gh_report?(actor, case_record, targets) do
    case Enum.find(targets, &(&1.reach == :not_installed)) do
      %{owner: owner, repo: repo} ->
        Cases.can_prepare_manual_report?(actor, case_record.id, owner, repo, "")

      nil ->
        false
    end
  end

  defp check_gh_answer(%{assigns: %{gh: %{request: %{id: id}}}} = socket) do
    case Cases.get_github_manual_request(id, actor: socket.assigns.current_user) do
      {:ok, %{completed_at: %DateTime{}}} ->
        socket
        |> assign(gh: nil, gh_link?: false)
        |> put_flash(:info, "GitHub's answer arrived and is recorded.")

      _pending ->
        socket
    end
  end

  defp check_gh_answer(socket), do: socket

  defp check_reach(socket, %GitHubAdvisoryLink{owner: owner, repo: repo}) when is_binary(owner) and is_binary(repo) do
    cond do
      socket.assigns.reach_for == {owner, repo} ->
        socket

      connected?(socket) ->
        actor = socket.assigns.current_user

        socket
        |> assign(reach: nil, reach_for: {owner, repo})
        |> start_async(:reach, fn -> Credentials.reach(actor, owner, repo) end)

      true ->
        socket
    end
  end

  defp check_reach(socket, %GitHubAdvisoryLink{}), do: assign(socket, reach: :public_read, reach_for: :global)

  defp check_reach(socket, nil), do: assign(socket, reach: nil, reach_for: nil)

  # A create cannot be asked about before its row exists, so the case's own
  # edit action, which the link's create defers to, answers for linking.
  defp permissions(actor, case_record, nil) do
    %{
      can_link?: Cases.can_edit_case?(actor, case_record, %{}, validate?: true),
      can_report?: Cases.can_report_case_to_github?(actor, case_record),
      can_grant?: false,
      can_unlink?: false,
      can_refresh?: false,
      can_pull?: false,
      can_push?: false
    }
  end

  defp permissions(actor, case_record, link) do
    %{
      can_link?: false,
      can_report?: false,
      can_grant?: Ash.can?({case_record, :grant_access}, actor),
      can_unlink?: Cases.can_unlink_github_advisory?(actor, link, %{}, validate?: true),
      can_refresh?: Cases.can_refresh_github_advisory_link?(actor, link, %{}, validate?: true),
      can_pull?: Cases.can_pull_github_advisory?(actor, link, [:title], %{}, validate?: true),
      can_push?: Cases.can_push_github_advisory?(actor, link, [:title], %{}, validate?: true)
    }
  end

  defp on_case(case_record) do
    assigned =
      for %{user: %{github_username: login}} <- case_record.assignments, is_binary(login) do
        {String.downcase(login), :assigned}
      end

    invited =
      for %{strategy: :github, username: login} <- case_record.invites do
        {login |> to_string() |> String.downcase(), :invited}
      end

    Map.new(invited ++ assigned)
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

  defp assign_report_form(%{assigns: %{report_form: %{}}} = socket, _case_record, nil), do: socket

  defp assign_report_form(socket, case_record, nil) do
    form =
      case_record
      |> AshPhoenix.Form.for_update(:report_to_github,
        as: "report",
        actor: socket.assigns.current_user,
        params: %{"description" => Export.description(case_record)}
      )
      |> to_form()

    assign(socket, report_form: form)
  end

  defp assign_report_form(socket, _case_record, _link), do: assign(socket, report_form: nil)

  defp resolve_audience(socket, nil), do: assign(socket, audience: nil, audience_for: nil)

  defp resolve_audience(%{assigns: %{audience_for: resolved}} = socket, %{id: id, fetched_at: at})
       when resolved == {id, at}, do: socket

  defp resolve_audience(socket, link) do
    if connected?(socket) do
      actor = socket.assigns.current_user

      socket
      |> assign(audience: nil, audience_for: {link.id, link.fetched_at})
      |> start_async(:audience, fn -> Audience.resolve(link, actor) end)
    else
      socket
    end
  end

  defp check_report_targets(socket, case_record) do
    repositories =
      if report_offered?(socket), do: ReportTargets.repositories(case_record), else: []

    if repositories == socket.assigns.report_targets_for do
      socket
    else
      socket
      |> assign(
        report_targets: Enum.map(repositories, &Map.merge(&1, %{reach: nil, private_reporting: :unknown})),
        report_targets_for: repositories
      )
      |> select_repository(socket.assigns.repository)
      |> ask_report_targets(repositories)
    end
  end

  defp report_offered?(socket) do
    connected?(socket) and socket.assigns.can_report?
  end

  defp ask_report_targets(socket, []), do: socket

  defp ask_report_targets(socket, repositories) do
    actor = socket.assigns.current_user
    start_async(socket, :report_targets, fn -> ReportTargets.list(repositories, actor) end)
  end

  defp select_repository(socket, choice) do
    targets = socket.assigns.report_targets
    selected = Enum.find(targets, List.first(targets), &(repository_name(&1) == choice))

    assign(socket, repository: selected && repository_name(selected), report_target: selected)
  end

  defp repository_name(%{owner: owner, repo: repo}), do: "#{owner}/#{repo}"

  defp link_params(socket, params), do: Map.put(params, "case_id", socket.assigns.case_record.id)

  defp gh_link?(socket, form, params) do
    not_installed = Credentials.message(:not_installed)
    %{case_record: case_record, current_user: actor} = socket.assigns

    Enum.any?(AshPhoenix.Form.errors(form), &match?({:advisory_url, ^not_installed}, &1)) and
      Cases.can_prepare_manual_link?(actor, case_record.id, params["advisory_url"])
  end

  defp open_gh(socket, {:ok, request}) do
    assign(socket, gh: %{request: request, token: request.__metadata__.token})
  end

  defp open_gh(socket, {:error, error}), do: put_flash(socket, :error, errors_to_string(error))

  defp report_params(socket, params) do
    case socket.assigns.report_target do
      %{owner: owner, repo: repo} -> Map.merge(params, %{"owner" => owner, "repo" => repo})
      nil -> params
    end
  end

  @impl Phoenix.LiveView
  def handle_event("validate", %{"form" => params}, socket) do
    form = AshPhoenix.Form.validate(socket.assigns.form, link_params(socket, params))
    {:noreply, assign(socket, form: form, gh_link?: false)}
  end

  def handle_event("link_advisory", %{"form" => params}, socket) do
    case AshPhoenix.Form.submit(socket.assigns.form, params: link_params(socket, params)) do
      {:ok, link} ->
        {:noreply, put_flash(socket, :info, "Linked #{link.ghsa_id}.")}

      {:error, form} ->
        {:noreply, assign(socket, form: form, gh_link?: gh_link?(socket, form, params))}
    end
  end

  def handle_event("gh_link", _params, socket) do
    %{case_record: case_record, current_user: actor, form: form} = socket.assigns
    url = AshPhoenix.Form.value(form, :advisory_url)

    {:noreply, open_gh(socket, Cases.prepare_manual_link(case_record.id, url, actor: actor))}
  end

  def handle_event("gh_refresh", _params, socket) do
    %{link: link, current_user: actor} = socket.assigns
    {:noreply, open_gh(socket, Cases.prepare_manual_refresh(link.id, actor: actor))}
  end

  def handle_event("gh_pull", %{"fields" => fields}, socket) do
    %{link: link, current_user: actor} = socket.assigns
    fields = String.split(fields, ",", trim: true)
    {:noreply, open_gh(socket, Cases.prepare_manual_pull(link.id, fields, actor: actor))}
  end

  def handle_event("gh_push", %{"fields" => fields}, socket) do
    %{link: link, current_user: actor} = socket.assigns
    fields = String.split(fields, ",", trim: true)
    {:noreply, open_gh(socket, Cases.prepare_manual_push(link.id, fields, actor: actor))}
  end

  def handle_event("close_gh", _params, socket), do: {:noreply, assign(socket, gh: nil)}

  def handle_event("report_to_github", %{"report" => params, "via" => "gh"} = all, socket) do
    socket = select_repository(socket, all["repository"])
    %{case_record: case_record, current_user: actor, report_target: target} = socket.assigns

    request =
      Cases.prepare_manual_report(
        case_record.id,
        target.owner,
        target.repo,
        params["description"],
        %{draft: all["gh_kind"] != "report"},
        actor: actor
      )

    {:noreply, open_gh(socket, request)}
  end

  def handle_event(event, _params, %{assigns: %{busy?: true}} = socket) when event in @github_requests do
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

  def handle_event("grant_access", %{"login" => login}, socket) do
    %{case_record: case_record, current_user: actor} = socket.assigns

    socket =
      case Cases.grant_case_access(case_record, :github, login, %{email_optional: true}, actor: actor) do
        {:ok, _case_record} -> put_flash(socket, :info, "#{login} has access to the case.")
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  def handle_event("validate_report", %{"report" => params} = all, socket) do
    socket = select_repository(socket, all["repository"])
    form = AshPhoenix.Form.validate(socket.assigns.report_form, report_params(socket, params))

    {:noreply, assign(socket, report_form: form, gh_kind: all["gh_kind"] || socket.assigns.gh_kind)}
  end

  def handle_event("report_to_github", %{"report" => params} = all, socket) do
    socket = select_repository(socket, all["repository"])
    form = socket.assigns.report_form
    params = report_params(socket, params)

    {:noreply,
     socket
     |> assign(busy?: true)
     |> start_async(:report, fn -> AshPhoenix.Form.submit(form, params: params) end)}
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

  def handle_async(:report, {:ok, result}, socket) do
    socket =
      case result do
        {:ok, %{__metadata__: %{github_report: :draft}}} ->
          put_flash(socket, :info, "Opened a draft advisory on GitHub.")

        {:ok, _case_record} ->
          put_flash(socket, :info, "Reported to the maintainers on GitHub.")

        {:error, form} ->
          assign(socket, report_form: form)
      end

    {:noreply, assign(socket, busy?: false)}
  end

  def handle_async(:reach, {:ok, reach}, socket), do: {:noreply, socket |> assign(reach: reach) |> assign_gh_offers()}

  def handle_async(:reach, {:exit, reason}, socket) do
    Logger.warning("Reach lookup for case #{socket.assigns.case_id} exited: #{inspect(reason)}")
    {:noreply, socket |> assign(reach: :unknown) |> assign_gh_offers()}
  end

  def handle_async(:audience, {:ok, audience}, socket) do
    {:noreply, assign(socket, audience: audience)}
  end

  def handle_async(:audience, {:exit, _reason}, socket) do
    {:noreply, assign(socket, audience: nil, audience_for: nil)}
  end

  def handle_async(:report_targets, {:ok, targets}, socket) do
    if Enum.map(targets, &Map.take(&1, [:owner, :repo])) == socket.assigns.report_targets_for do
      {:noreply,
       socket
       |> assign(report_targets: targets)
       |> select_repository(socket.assigns.repository)
       |> assign_gh_offers()}
    else
      {:noreply, socket}
    end
  end

  def handle_async(:report_targets, {:exit, _reason}, socket), do: {:noreply, socket}

  def handle_async(task, {:exit, reason}, socket) when task in [:refresh, :push, :report] do
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
        tabs={CaseLifecycle.tabs(@case_record)}
        active={@live_action}
      >
        <:actions>
          <CaseLifecycle.lifecycle_buttons case_record={@case_record} current_user={@current_user} />
        </:actions>
      </.case_header>

      <.page_container width={:wide} class="space-y-4">
        <div
          :if={!@github_identity? and not Credentials.acts?(@reach)}
          id="github-identity-notice"
          class="alert alert-info text-sm"
        >
          <.icon name="hero-information-circle" class="size-5 shrink-0" />
          <span>
            Draft advisories are read and written with your GitHub account, and none is linked
            to yours.
            <.link navigate={~p"/settings/account"} class="link link-hover font-semibold">
              Link GitHub in account settings
            </.link>
            to refresh, push and report from here.
          </span>
        </div>

        <%= if @link do %>
          <.reach_notice
            :if={@github_identity?}
            id="github-reach-notice"
            reach={@reach}
            gh={@gh_offers.refresh}
          />
          <.advisory_card
            link={@link}
            can_refresh={Credentials.acts?(@reach) and @can_refresh?}
            gh_refresh={@gh_offers.refresh}
            can_unlink={@can_unlink?}
            busy={@busy?}
          />
          <.advisory_audience
            :if={@audience_for}
            audience={@audience}
            on_case={@on_case}
            can_grant={@can_grant?}
            loading={is_nil(@audience)}
          />
          <.advisory_diff
            rows={@link.diff}
            can_pull={@can_pull?}
            can_push={Credentials.acts?(@reach) and @can_push?}
            gh_pull={@gh_offers.pull}
            gh_push={@gh_offers.push}
            busy={@busy?}
          />
        <% else %>
          <.panel id="link-advisory">
            <:title>GitHub advisory</:title>
            <div :if={@can_link? and @may_try?}>
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
              <div :if={@gh_link?} id="gh-link-offer" class="mt-2 flex flex-wrap items-center gap-2">
                <span class="text-sm text-base-content/60">
                  You can read it with your own GitHub account instead.
                </span>
                <button type="button" phx-click="gh_link" class="btn btn-xs btn-eef-quiet">
                  Link with gh
                </button>
              </div>
            </div>
            <.empty_state :if={!(@can_link? and @may_try?)} class="py-4">
              No advisory is linked to this case.
            </.empty_state>
          </.panel>

          <.report_panel
            :if={@can_report? and @report_targets != []}
            form={@report_form}
            targets={@report_targets}
            target={@report_target}
            gh={@gh_offers.report}
            gh_kind={@gh_kind}
            busy={@busy?}
          />
        <% end %>
      </.page_container>

      <.gh_command_modal
        :if={@gh}
        request={@gh.request}
        token={@gh.token}
        base_url={VarselWeb.Endpoint.url()}
      />

      <CaseLifecycle.cve_picker_modal
        :if={@cve_picker}
        case_record={@case_record}
        current_user={@current_user}
        records={@cve_picker}
      />
    </Layouts.app>
    """
  end

  attr :form, Phoenix.HTML.Form, required: true
  attr :targets, :list, required: true
  attr :target, :map, required: true, doc: "the target the repository select names"

  attr :gh, :boolean,
    required: true,
    doc: "whether a repository without the App is offered as a gh command"

  attr :gh_kind, :string, required: true, doc: "`draft` or `report`, the choice for a gh command"
  attr :busy, :boolean, required: true

  defp report_panel(assigns) do
    %{reach: reach, private_reporting: private_reporting} = assigns.target

    assigns =
      assign(assigns,
        options: Enum.map(assigns.targets, &{repository_name(&1), repository_name(&1)}),
        app?: reach == :installation,
        gh?: assigns.gh and reach == :not_installed,
        reporting_off?: reach == :user and private_reporting == false,
        disabled: not Credentials.acts?(reach) or (reach == :user and private_reporting == false)
      )

    ~H"""
    <.panel id="report-advisory">
      <:title>Report to GitHub</:title>
      <p class="text-sm text-base-content/60 mb-3">
        Report the case to a repository's maintainers as a private vulnerability report, as
        you, or open a draft advisory where you administer the repository. Everything the case
        states goes with it. The description below is the case's advisory text, which the
        maintainers will read, so edit it for them.
      </p>
      <.form
        for={@form}
        id="report-advisory-form"
        phx-change="validate_report"
        phx-submit="report_to_github"
        class="space-y-2"
      >
        <.input
          id="report-repository"
          name="repository"
          type="select"
          value={repository_name(@target)}
          options={@options}
          errors={Enum.map(@form[:repo].errors, &translate_error/1)}
          class="select select-bordered select-sm w-full max-w-xl"
        >
          <:label>Repository</:label>
        </.input>
        <.reach_notice id="report-reach-notice" reach={@target.reach} gh={@gh?} />
        <p :if={@app?} id="report-as-app" class="text-sm text-base-content/60">
          Your GitHub login cannot report to {repository_name(@target)}, so the EEF CNA app
          opens a draft advisory there instead, which the repository's maintainers see.
        </p>
        <div :if={@reporting_off?} id="reporting-disabled" class="alert alert-warning text-sm">
          <.icon name="hero-exclamation-triangle" class="size-5 shrink-0" />
          <span>
            {repository_name(@target)} does not accept private vulnerability reports. Ask the
            maintainers to turn them on, as the
            <.link
              href={~p"/maintainer-process" <> "#2-preferred-channel-github-private-vulnerability-reporting"}
              target="_blank"
              class="link link-hover font-semibold"
            >
              maintainer process
            </.link>
            describes.
          </span>
        </div>
        <.input
          field={@form[:description]}
          type="textarea"
          required
          rows="8"
          class="textarea textarea-bordered w-full text-sm"
        >
          <:label>Description for the maintainers</:label>
        </.input>
        <fieldset :if={@gh?} id="report-gh-kind" class="fieldset">
          <legend class="fieldset-legend">With gh, as your GitHub account</legend>
          <label class="label text-sm">
            <input
              type="radio"
              name="gh_kind"
              value="draft"
              class="radio radio-sm"
              checked={@gh_kind != "report"}
            /> Open a draft advisory: you administer {repository_name(@target)}
          </label>
          <label class="label text-sm">
            <input
              type="radio"
              name="gh_kind"
              value="report"
              class="radio radio-sm"
              checked={@gh_kind == "report"}
            /> Report privately: you do not administer it
          </label>
        </fieldset>
        <button
          :if={@gh?}
          type="submit"
          name="via"
          value="gh"
          class="btn btn-sm btn-eef"
          disabled={@busy}
        >
          Report with gh
        </button>
        <button
          :if={!@gh?}
          type="submit"
          class="btn btn-sm btn-eef"
          disabled={@busy or @disabled}
          data-confirm={
            if(@app?,
              do: "Open this draft advisory on GitHub as the EEF CNA app?",
              else: "Send this report to the maintainers on GitHub as you?"
            )
          }
        >
          {if(@app?, do: "Open a draft advisory", else: "Report privately")}
        </button>
      </.form>
    </.panel>
    """
  end

  attr :id, :string, required: true

  attr :reach, :any,
    required: true,
    doc: "a `Varsel.GitHub.Credentials.reach/3` answer, or nil while unknown"

  attr :gh, :boolean, default: false, doc: "whether the actions here are offered as gh commands"

  defp reach_notice(%{reach: :not_reachable} = assigns) do
    ~H"""
    <div id={@id} class="alert alert-info text-sm">
      <.icon name="hero-information-circle" class="size-5 shrink-0" />
      <span>
        Your GitHub login cannot act on this repository. The repository's owner needs to
        install the EEF CNA app.
        <.link navigate={~p"/settings/account"} class="link link-hover font-semibold">
          Account settings
        </.link>
        show where the app can act for you, with a Refresh for after an install.
      </span>
    </div>
    """
  end

  defp reach_notice(%{reach: :not_installed} = assigns) do
    ~H"""
    <div id={@id} class="alert alert-info text-sm">
      <.icon name="hero-information-circle" class="size-5 shrink-0" />
      <span>
        This cannot be done from here: the EEF CNA app is not installed on this repository.
        <span :if={@gh}>
          Do it with gh instead: each action gives you a command to run in your own terminal,
          as your GitHub account.
        </span>
      </span>
    </div>
    """
  end

  defp reach_notice(%{reach: reach} = assigns)
       when reach in [nil, :user, :installation, :public_read, :no_github_identity], do: ~H""

  defp reach_notice(%{reach: :unknown} = assigns) do
    ~H"""
    <div id={@id} class="alert alert-warning text-sm">
      <.icon name="hero-exclamation-triangle" class="size-5 shrink-0" />
      <span>This page could not tell what your GitHub login can do here. Reload to try again.</span>
    </div>
    """
  end

  defp reach_notice(assigns) do
    ~H"""
    <div id={@id} class="alert alert-warning text-sm">
      <.icon name="hero-exclamation-triangle" class="size-5 shrink-0" />
      <span>This page {Credentials.message(@reach)}.</span>
    </div>
    """
  end
end
