# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.DevNav do
  @moduledoc """
  Floating dev-tools launcher, pinned to the bottom-right of every page.

  Hovering the `</>` disc opens the tooling index — storybook, dashboards,
  admin, mailbox, error previews — plus the GitHub-bypassing mock logins while
  signed out. Kept out of the site header so the real chrome stays honest.

  Lives under `dev/`, only compiled for `:dev` and `:test`; the layout renders
  it behind the same `Mix.env/0` check.

  `~p` here verifies against `VarselWeb.DevRouter` rather than the app router:
  these paths are declared there, and the main router only reaches them through
  a forward, which verified routes cannot see through.
  """

  use Phoenix.Component

  use Phoenix.VerifiedRoutes,
    endpoint: VarselWeb.Endpoint,
    router: VarselWeb.DevRouter,
    statics: VarselWeb.static_paths()

  import VarselWeb.CoreComponents, only: [icon: 1]

  # `~p` is expanded at compile time, so the paths have to be literal here
  # rather than carried in a module attribute.
  defp tools do
    [
      {"Storybook", ~p"/dev/storybook", "hero-swatch"},
      {"AshAdmin", ~p"/dev/admin", "hero-circle-stack"},
      {"Oban", ~p"/dev/oban", "hero-queue-list"},
      {"LiveDashboard", ~p"/dev/dashboard", "hero-chart-bar"},
      {"Mailbox", ~p"/dev/mailbox", "hero-envelope"},
      {"Error pages", ~p"/dev/http-error/404", "hero-exclamation-triangle"}
    ]
  end

  @mock_roles [{"POC", "poc"}, {"Supporter", "supporter"}, {"No role", "none"}]

  attr :current_user, :any, default: nil

  def dev_nav(assigns) do
    assigns = assign(assigns, tools: tools(), roles: @mock_roles)

    ~H"""
    <div class="group fixed bottom-4 right-4 z-[60] print:hidden">
      <%!-- The panel sits inside the group and above the disc, so moving the
            pointer from one to the other never leaves the hover area. --%>
      <div class="invisible absolute bottom-full right-0 pb-2 opacity-0 transition-opacity group-hover:visible group-hover:opacity-100 focus-within:visible focus-within:opacity-100">
        <div class="w-56 rounded-box border border-base-300 bg-base-100 p-2 shadow-lg">
          <p class="px-2 pb-1 text-[0.68rem] font-bold uppercase tracking-wider text-base-content/50">
            Dev tools
          </p>
          <ul class="space-y-0.5 text-sm">
            <li :for={{label, path, icon} <- @tools}>
              <a
                href={path}
                class="flex items-center gap-2 rounded px-2 py-1.5 text-base-content hover:bg-base-200"
              >
                <.icon name={icon} class="size-4 shrink-0 text-base-content/50" />
                {label}
              </a>
            </li>
          </ul>

          <div :if={is_nil(@current_user)} class="mt-1.5 border-t border-base-300 pt-1.5">
            <p class="px-2 pb-1 text-[0.68rem] font-bold uppercase tracking-wider text-base-content/50">
              Mock sign in
            </p>
            <ul class="space-y-0.5 text-sm">
              <li :for={{label, role} <- @roles}>
                <.link
                  href={~p"/dev/mock-auth/sign-in/#{role}"}
                  method="post"
                  class="flex items-center gap-2 rounded px-2 py-1.5 text-base-content hover:bg-base-200"
                >
                  <.icon name="hero-beaker" class="size-4 shrink-0 text-warning" />
                  {label}
                </.link>
              </li>
            </ul>
          </div>
        </div>
      </div>

      <button
        type="button"
        aria-label="Dev tools"
        class="flex size-11 cursor-pointer items-center justify-center rounded-full border border-base-300 bg-base-100 text-base-content/70 shadow-lg transition-colors hover:bg-base-200 hover:text-base-content"
      >
        <.icon name="hero-code-bracket" class="size-5" />
      </button>
    </div>
    """
  end
end
