# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.DevRouter do
  @moduledoc """
  Routes for the developer tooling: the component storybook, Oban Web, the
  LiveDashboard, AshAdmin, the Swoosh mailbox preview and the error-page
  preview.

  Lives under `dev/`, a directory `elixirc_paths/1` only compiles for `:dev`
  and `:test`, which is what keeps these routes out of production — the
  storybook, Oban Web and LiveDashboard dependencies do not even exist in a
  production build, and Elixir resolves an `import` regardless of the branch
  it sits in, so a compile-time flag in the main router would not be enough.

  `VarselWeb.Router` forwards here from the root under the same `Mix.env/0`
  check.
  """

  use VarselWeb, :router
  use AshAuthentication.Phoenix.Router

  import AshAdmin.Router
  import Oban.Web.Router
  import Phoenix.LiveDashboard.Router
  import PhoenixStorybook.Router

  # The tools all rely on inline scripts/styles, eval and CDN assets that the
  # app-wide strict CSP forbids. They never run in production, so the strict
  # header is replaced with Phoenix's own secure-browser default — enough to
  # keep the clickjacking and base-tag protections without constraining the
  # tools.
  pipeline :dev_browser do
    plug :accepts, ["html", "json"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {VarselWeb.Layouts, :root}
    plug :put_secure_browser_headers
    plug :load_from_session
    plug :set_actor, :user
    plug AshGraphql.Plug

    plug PlugContentSecurityPolicy,
      nonces_for: [],
      directives: %{
        base_uri: ~w('self'),
        frame_ancestors: ~w('self')
      }
  end

  # Every path here is declared in full, including the `/dev` segment, and the
  # main router forwards this module at the ROOT rather than at "/dev". These
  # tools build their own redirects (`/dev/storybook` -> the first story,
  # `/dev/dashboard` -> its home page) from the path they were mounted at, and
  # a plug forward is invisible to them: mounted under "/dev" with a
  # "/storybook" route they would send the browser to `/storybook/welcome`,
  # which does not exist.
  scope "/" do
    storybook_assets("/dev/storybook/assets")
  end

  scope "/" do
    pipe_through :dev_browser

    get "/dev/http-error/:status", VarselWeb.DevErrorPreviewController, :show
    forward "/dev/mailbox", Plug.Swoosh.MailboxPreview

    live_dashboard "/dev/dashboard", metrics: VarselWeb.Telemetry
    oban_dashboard("/dev/oban")
    ash_admin "/dev/admin"

    live_storybook "/dev/storybook",
      backend_module: VarselWeb.Storybook,
      assets_path: "/dev/storybook/assets"

    # Irrelevant: compile time, not runtime.
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    forward "/dev/graphiql", Absinthe.Plug.GraphiQL,
      # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
      schema: Module.concat(["VarselWeb.GraphqlSchema"]),
      interface: :simple
  end
end
