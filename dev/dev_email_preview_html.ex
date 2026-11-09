# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.DevEmailPreviewHTML do
  @moduledoc """
  Renders `VarselWeb.DevEmailPreviewController`'s email picker and the
  selected email's HTML and text parts side by side.
  """
  use Phoenix.Component

  import VarselWeb.CoreComponents, only: [page_header: 1]

  alias VarselWeb.Layouts

  use Phoenix.VerifiedRoutes,
    endpoint: VarselWeb.Endpoint,
    router: VarselWeb.DevRouter,
    statics: VarselWeb.static_paths()

  def index(assigns) do
    ~H"""
    <Layouts.app
      flash={@flash}
      current_user={assigns[:current_user]}
      current_path={@conn.request_path}
    >
      <section class="console-band">
        <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6">
          <.page_header>
            <:eyebrow>Dev tools</:eyebrow>
            <:title>Email preview</:title>
            <:subtitle>
              Every email the app sends, rendered from sample data. Nothing is delivered.
            </:subtitle>
          </.page_header>
        </div>
      </section>

      <div class="mx-auto grid max-w-7xl gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[14rem_1fr]">
        <nav id="email-preview-list" aria-label="Emails" class="space-y-4 text-sm">
          <div :for={[first | _] = group <- Enum.chunk_by(@samples, & &1.group)}>
            <p class="eef-eyebrow px-2 pb-1">{first.group}</p>
            <ul class="space-y-0.5">
              <li :for={sample <- group}>
                <.link
                  id={"email-preview-link-#{sample.slug}"}
                  href={~p"/dev/emails?#{[email: sample.slug]}"}
                  aria-current={@selected && @selected.slug == sample.slug && "page"}
                  class={[
                    "block rounded px-2 py-1.5 hover:bg-base-200",
                    @selected && @selected.slug == sample.slug && "bg-base-200 font-semibold"
                  ]}
                >
                  {sample.label}
                </.link>
              </li>
            </ul>
          </div>
        </nav>

        <div :if={is_nil(@email)} id="email-preview-missing" class="alert alert-warning">
          No email by that name. Pick one from the list.
        </div>

        <div :if={@email} id="email-preview" class="min-w-0 space-y-4">
          <dl
            id="email-preview-headers"
            class="card grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 border border-base-300 bg-base-100 p-4 text-sm"
          >
            <dt class="text-base-content/60">Subject</dt>
            <dd class="font-semibold">{@email.subject}</dd>
            <dt class="text-base-content/60">From</dt>
            <dd>{format_address(@email.from)}</dd>
            <dt class="text-base-content/60">To</dt>
            <dd>{Enum.map_join(@email.to, ", ", &format_address/1)}</dd>
          </dl>

          <div class="grid gap-4 xl:grid-cols-2">
            <section id="email-preview-html" class="flex min-w-0 flex-col">
              <h2 class="eef-eyebrow pb-2">HTML</h2>
              <iframe
                :if={@email.html_body}
                title="HTML part"
                sandbox=""
                srcdoc={@email.html_body}
                class="h-[36rem] w-full rounded-box border border-base-300 bg-white"
              />
              <div
                :if={is_nil(@email.html_body)}
                class="flex h-[36rem] items-center justify-center rounded-box border border-dashed border-base-300 text-sm text-base-content/60"
              >
                This email has no HTML part.
              </div>
            </section>

            <section id="email-preview-text" class="flex min-w-0 flex-col">
              <h2 class="eef-eyebrow pb-2">Text</h2>
              <pre
                :if={@email.text_body}
                class="h-[36rem] overflow-auto whitespace-pre-wrap break-words rounded-box border border-base-300 bg-base-100 p-4 font-mono text-sm"
              >{@email.text_body}</pre>
              <div
                :if={is_nil(@email.text_body)}
                class="flex h-[36rem] items-center justify-center rounded-box border border-dashed border-base-300 text-sm text-base-content/60"
              >
                This email has no text part.
              </div>
            </section>
          </div>
        </div>
      </div>
    </Layouts.app>
    """
  end

  defp format_address({"", address}), do: address
  defp format_address({name, address}), do: "#{name} <#{address}>"
end
