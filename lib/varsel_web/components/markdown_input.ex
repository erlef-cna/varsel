# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.MarkdownInput do
  @moduledoc """
  Markdown editor form field with a Write/Preview switch.

  Preview renders through `Varsel.Cases.Markdown.to_display_html/1` — the
  same document semantics the published record uses (plus display-only code
  highlighting), so what you preview is what MITRE gets. The
  textarea stays in the DOM while previewing (only visually hidden): a form
  submitted mid-preview still carries the field's value.

  The Write/Preview switch is a hairline text-tab row (not boxed daisyUI
  tabs) matching the preview slide-over's tabs, with a faint "markdown"
  format hint at the row's right edge. Each field instance keeps its own
  write/preview state, since a form can hold several of these at once.

      <.live_component
        module={VarselWeb.MarkdownInput}
        id="case-description"
        field={@form[:description_md]}
        label="Description"
        rows={8}
      />

  With `flavor={:comment}` it is a comment composer: the preview renders as
  the comment will (`Varsel.Cases.Markdown.to_comment_html/2`, with the
  viewer's own mentions marked by `viewer_id`), and typing `@` offers the
  `mentionable` people (`[%{id: id, name: name}]`).
  """
  use VarselWeb, :live_component

  alias Varsel.Cases.Markdown

  @impl Phoenix.LiveComponent
  def mount(socket) do
    {:ok, assign(socket, mode: :write)}
  end

  @impl Phoenix.LiveComponent
  def update(assigns, socket) do
    {:ok,
     socket
     |> assign(assigns)
     |> assign_new(:rows, fn -> 6 end)
     |> assign_new(:placeholder, fn -> nil end)
     |> assign_new(:flavor, fn -> :document end)
     |> assign_new(:mentionable, fn -> [] end)
     |> assign_new(:viewer_id, fn -> nil end)}
  end

  @impl Phoenix.LiveComponent
  def handle_event("mode", %{"mode" => "preview"}, socket) do
    {:noreply, assign(socket, mode: :preview)}
  end

  def handle_event("mode", %{"mode" => "write"}, socket) do
    {:noreply, assign(socket, mode: :write)}
  end

  @impl Phoenix.LiveComponent
  def render(assigns) do
    ~H"""
    <div id={@id} class="mb-3" data-comment-composer={@flavor == :comment}>
      <label class="label text-sm mb-1" for={@field.id}>{@label}</label>
      <div class="flex items-center gap-4 border-b border-base-300 text-xs mb-2">
        <button
          type="button"
          class={["pb-1.5", tab_class(@mode == :write)]}
          phx-click="mode"
          phx-value-mode="write"
          phx-target={@myself}
        >
          Write
        </button>
        <button
          type="button"
          class={["pb-1.5", tab_class(@mode == :preview)]}
          phx-click="mode"
          phx-value-mode="preview"
          phx-target={@myself}
        >
          Preview
        </button>
        <span class="ml-auto pb-1.5 text-base-content/40">markdown</span>
      </div>

      <div data-autogrow-frame class={["relative", @mode == :preview && "hidden"]}>
        <.input
          field={@field}
          type="textarea"
          rows={@rows}
          placeholder={@placeholder}
          class="w-full textarea font-mono text-sm max-h-[80vh]"
          phx-hook="AutoGrow"
        />
        <div
          :if={@flavor == :comment}
          id={"#{@id}-assist"}
          phx-hook="CommentAssist"
          phx-update="ignore"
          data-candidates={Jason.encode!(@mentionable)}
        >
          <ul
            data-mention-menu
            role="listbox"
            aria-label="People to mention"
            class="hidden absolute top-0 left-0 z-30 w-64 max-h-60 overflow-y-auto rounded-box border border-base-300 bg-base-100 p-1 text-sm text-base-content shadow"
          >
          </ul>
        </div>
      </div>

      <p
        :if={@flavor == :comment and @mentionable != []}
        id={"#{@id}-mention-hint"}
        class={["mt-1 text-xs text-base-content/50", @mode == :preview && "hidden"]}
      >
        Type @ to mention someone in the case.
      </p>

      <div
        :if={@mode == :preview}
        class="prose prose-sm max-w-none border border-base-300 rounded-box bg-base-100 p-3 min-h-24"
      >
        {preview(@field.value, @flavor, @viewer_id)}
      </div>
    </div>
    """
  end

  defp tab_class(true), do: "font-bold text-base-content [box-shadow:inset_0_-2px_0_var(--color-primary)]"

  defp tab_class(false), do: "text-base-content/50 hover:text-base-content"

  # `to_display_html/2` and `to_comment_html/2` sanitize their output.
  # sobelow_skip ["XSS.Raw"]
  defp preview(value, flavor, viewer_id) do
    case value do
      value when value in [nil, ""] ->
        assigns = %{}

        ~H"""
        <p class="text-base-content/50 not-prose text-sm">Nothing to preview.</p>
        """

      markdown when flavor == :comment ->
        raw(Markdown.to_comment_html(to_string(markdown), viewer_id: viewer_id))

      markdown ->
        raw(Markdown.to_display_html(to_string(markdown)))
    end
  end
end
