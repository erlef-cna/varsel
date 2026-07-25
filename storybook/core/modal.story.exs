# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Core.Modal do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CoreComponents.modal/1

  def layout, do: :one_column

  # The modal covers the page it opens over, so each variation is pinned into
  # its own box here rather than over the whole storybook.
  def container, do: {:div, class: "relative h-72 [&_.modal]:absolute [&_.modal]:z-0"}

  def variations do
    [
      %Variation{
        id: :message,
        description: "The least a modal holds: something to read, and a way out.",
        attributes: %{id: "modal-message", title: "Assign a CVE ID", on_cancel: "noop"},
        slots: [
          "<p class=\"text-sm\">The next reserved ID will be attached to this case.</p>",
          """
          <:actions>
            <button class="btn btn-ghost btn-sm">Cancel</button>
            <button class="btn btn-primary btn-sm">Assign</button>
          </:actions>
          """
        ]
      },
      %Variation{
        id: :with_form,
        description:
          "A form inside puts its own action row in, so the submit button belongs to " <>
            "the form rather than the modal.",
        attributes: %{id: "modal-form", title: "Add reference", on_cancel: "noop"},
        slots: [
          """
          <form>
            <div class="fieldset mb-2">
              <label class="label mb-1">URL</label>
              <input type="text" class="w-full input" value="https://github.com/erlang/otp/commit/2691a80"/>
            </div>
            <div class="modal-action">
              <button type="button" class="btn btn-ghost btn-sm">Cancel</button>
              <button type="submit" class="btn btn-primary btn-sm">Save</button>
            </div>
          </form>
          """
        ]
      },
      %Variation{
        id: :wide,
        description: "`class` sets the box's measure for something that needs the room.",
        attributes: %{
          id: "modal-wide",
          title: "Record preview",
          on_cancel: "noop",
          class: "max-w-3xl"
        },
        slots: [
          """
          <div class="text-sm space-y-2">
            <p>A wider box for something that needs the room — the record preview
            opens over the workspace at this measure.</p>
            <p class="text-base-content/60">Validation, the rendered record, and the
            diff against what is published each get a tab along its top.</p>
          </div>
          """
        ]
      }
    ]
  end
end
