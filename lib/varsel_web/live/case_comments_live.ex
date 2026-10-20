# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseCommentsLive do
  @moduledoc """
  The Comments tab of a case: the whole discussion stream, oldest first, and
  the form to add to it.

  The workspace rail shows the newest activity next to the content it is
  about. This tab is where the stream is read in full and where a comment is
  written with a preview.

  A case linked to a GitHub advisory also shows the advisory's own comments,
  read every five minutes. GitHub keeps its confidential comments out of its
  API, so that part of the stream is never complete and says so.
  """
  use VarselWeb, :live_view

  import VarselWeb.CaseComponents, only: [case_header: 1, comment_card: 1]

  alias Varsel.Cases.Comment
  alias VarselWeb.CaseLifecycle

  @impl Phoenix.LiveView
  def mount(%{"id" => id}, _session, socket) do
    socket =
      CaseLifecycle.mount(socket, id,
        load: [
          :cve_id,
          :cve_record,
          :github_advisory_link,
          comments: [author: [:avatar_url, :display_name]]
        ],
        after_fetch: &after_fetch/2,
        marks_read: [:comment_posted]
      )

    {:ok, socket}
  end

  defp after_fetch(case_record, socket) do
    socket
    |> assign(
      page_title: case_record.title || "Case",
      comments: Enum.sort_by(case_record.comments, & &1.inserted_at, DateTime)
    )
    |> assign_new(:form, fn -> comment_form(socket.assigns.current_user) end)
  end

  defp comment_form(actor) do
    Comment
    |> AshPhoenix.Form.for_create(:post, as: "form", actor: actor)
    |> to_form()
  end

  @impl Phoenix.LiveView
  def handle_event("validate_comment", %{"form" => params}, socket) do
    {:noreply, assign(socket, :form, AshPhoenix.Form.validate(socket.assigns.form, params))}
  end

  def handle_event("post_comment", %{"form" => params}, socket) do
    params = Map.put(params, "case_id", socket.assigns.case_record.id)

    case AshPhoenix.Form.submit(socket.assigns.form, params: params) do
      {:ok, _comment} ->
        {:noreply, assign(socket, :form, comment_form(socket.assigns.current_user))}

      {:error, form} ->
        {:noreply, assign(socket, :form, form)}
    end
  end

  # The comment create policy reaches the actor through the case's
  # assignments, which no row yet relates to at the strict step, so
  # `can_post_case_comment?` answers true for anyone. Reading the case asks
  # the same POC-or-assigned question about a row that exists.
  defp can_comment?(case_record, actor), do: Ash.can?({case_record, :read}, actor)

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
        active={:comments}
      >
        <:actions>
          <CaseLifecycle.lifecycle_buttons case_record={@case_record} current_user={@current_user} />
        </:actions>
      </.case_header>

      <.page_container class="space-y-4">
        <p :if={@case_record.github_advisory_link} class="text-xs text-base-content/60">
          <.icon name="hero-information-circle-micro" class="size-4 align-text-bottom" />
          The comments on the linked GitHub advisory are read every five minutes and shown here.
          GitHub does not serve confidential comments, so its discussion may hold more than this.
        </p>

        <div class="space-y-3">
          <.comment_card
            :for={comment <- @comments}
            row_id={"comment-#{comment.id}"}
            comment={comment}
          />
          <p :if={@comments == []} class="text-sm text-base-content/60">No comments yet.</p>
        </div>

        <.panel :if={can_comment?(@case_record, @current_user)}>
          <:title>Add a comment</:title>
          <.form
            for={@form}
            id="case-comment-form"
            phx-change="validate_comment"
            phx-submit="post_comment"
          >
            <.live_component
              module={VarselWeb.MarkdownInput}
              id="case-comment-body"
              field={@form[:body]}
              label="Comment"
              rows={6}
              placeholder="Write a comment…"
            />
            <button type="submit" class="btn btn-eef btn-sm" phx-disable-with="Posting…">
              Comment
            </button>
          </.form>
        </.panel>
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
end
