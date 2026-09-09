# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseGitHubLive do
  @moduledoc """
  The GitHub tab of a case: the security advisory it is linked to, read as
  the person looking, who sees it on GitHub, and the case set against it
  field by field. A case without an advisory reports itself to a
  repository's maintainers from here.
  """
  use VarselWeb, :live_view

  import VarselWeb.AdvisoryComponents
  import VarselWeb.CaseComponents, only: [case_header: 1]

  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisory.Audience
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.Cases.GitHubAdvisory.ReportTargets
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.GitHub.UserToken
  alias VarselWeb.CaseLifecycle

  @github_requests ["refresh_advisory", "push_advisory", "report_to_github"]

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    socket =
      socket
      |> assign(
        busy?: false,
        github_identity?: UserToken.linked?(socket.assigns.current_user),
        audience: nil,
        audience_for: nil,
        report_targets: [],
        report_targets_for: nil,
        repository: nil,
        report_target: nil
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
    |> check_report_targets(case_record)
  end

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
        report_targets: Enum.map(repositories, &Map.put(&1, :private_reporting, :unknown)),
        report_targets_for: repositories
      )
      |> select_repository(socket.assigns.repository)
      |> ask_report_targets(repositories)
    end
  end

  defp report_offered?(socket) do
    connected?(socket) and socket.assigns.github_identity? and socket.assigns.can_report?
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

  defp report_params(socket, params) do
    case socket.assigns.report_target do
      %{owner: owner, repo: repo} -> Map.merge(params, %{"owner" => owner, "repo" => repo})
      nil -> params
    end
  end

  @impl Phoenix.LiveView
  def handle_event("validate", %{"form" => params}, socket) do
    form = AshPhoenix.Form.validate(socket.assigns.form, link_params(socket, params))
    {:noreply, assign(socket, form: form)}
  end

  def handle_event("link_advisory", %{"form" => params}, socket) do
    case AshPhoenix.Form.submit(socket.assigns.form, params: link_params(socket, params)) do
      {:ok, link} -> {:noreply, put_flash(socket, :info, "Linked #{link.ghsa_id}.")}
      {:error, form} -> {:noreply, assign(socket, form: form)}
    end
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
    {:noreply, assign(socket, report_form: form)}
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
          put_flash(socket, :info, "Opened a draft advisory on GitHub in your name.")

        {:ok, _case_record} ->
          put_flash(socket, :info, "Reported to the maintainers on GitHub.")

        {:error, form} ->
          assign(socket, report_form: form)
      end

    {:noreply, assign(socket, busy?: false)}
  end

  def handle_async(:audience, {:ok, audience}, socket) do
    {:noreply, assign(socket, audience: audience)}
  end

  def handle_async(:audience, {:exit, _reason}, socket) do
    {:noreply, assign(socket, audience: nil, audience_for: nil)}
  end

  def handle_async(:report_targets, {:ok, targets}, socket) do
    if Enum.map(targets, &Map.take(&1, [:owner, :repo])) == socket.assigns.report_targets_for do
      {:noreply, socket |> assign(report_targets: targets) |> select_repository(socket.assigns.repository)}
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
        tabs={CaseLifecycle.tabs(@case_record.id)}
        active={@live_action}
      >
        <:actions>
          <CaseLifecycle.lifecycle_buttons case_record={@case_record} current_user={@current_user} />
        </:actions>
      </.case_header>

      <.page_container width={:wide} class="space-y-4">
        <div :if={!@github_identity?} id="github-identity-notice" class="alert alert-info text-sm">
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
          <.advisory_card
            link={@link}
            can_refresh={@github_identity? and @can_refresh?}
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
            can_push={@github_identity? and @can_push?}
            busy={@busy?}
          />
        <% else %>
          <.panel id="link-advisory">
            <:title>GitHub advisory</:title>
            <div :if={@can_link?}>
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
            </div>
            <.empty_state :if={!@can_link?} class="py-4">
              No advisory is linked to this case.
            </.empty_state>
          </.panel>

          <.report_panel
            :if={@github_identity? and @can_report? and @report_targets != []}
            form={@report_form}
            targets={@report_targets}
            target={@report_target}
            busy={@busy?}
          />
        <% end %>
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

  attr :form, Phoenix.HTML.Form, required: true
  attr :targets, :list, required: true
  attr :target, :map, required: true, doc: "the target the repository select names"
  attr :busy, :boolean, required: true

  defp report_panel(assigns) do
    assigns =
      assign(assigns,
        options: Enum.map(assigns.targets, &{repository_name(&1), repository_name(&1)}),
        disabled: assigns.target.private_reporting == false
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
        <div :if={@disabled} id="reporting-disabled" class="alert alert-warning text-sm">
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
        <button
          type="submit"
          class="btn btn-sm btn-eef"
          disabled={@busy or @disabled}
          data-confirm="Send this report to the maintainers on GitHub as you?"
        >
          Report privately
        </button>
      </.form>
    </.panel>
    """
  end
end
