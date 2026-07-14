# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Router do
  use VarselWeb, :router
  use AshAuthentication.Phoenix.Router

  import AshAuthentication.Plug.Helpers

  alias Elixir.AshAuthentication.Phoenix.Overrides.DaisyUI
  alias Varsel.Accounts.User
  alias VarselWeb.Plugs.ApiKeyAuth

  pipeline :graphql do
    plug ApiKeyAuth
    plug :load_from_bearer
    plug :set_actor, :user
    plug AshGraphql.Plug
  end

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {VarselWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :load_from_session
  end

  # Auth pages (sign in / register / reset / confirm) use a bare, centered
  # layout with no site nav or footer.
  pipeline :auth_browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {VarselWeb.Layouts, :root_auth}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :load_from_session
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug ApiKeyAuth
    plug :load_from_bearer
    plug :set_actor, :user
  end

  # MCP tool calls read the actor from the conn (Ash.PlugHelpers); anonymous
  # requests keep actor nil, so public tools work without a key.
  pipeline :mcp do
    plug ApiKeyAuth
  end

  scope "/gql" do
    pipe_through [:graphql]

    forward "/playground", Absinthe.Plug.GraphiQL,
      schema: Module.concat(["VarselWeb.GraphqlSchema"]),
      socket: Module.concat(["VarselWeb.GraphqlSocket"]),
      interface: :simple

    forward "/", Absinthe.Plug, schema: Module.concat(["VarselWeb.GraphqlSchema"])
  end

  scope "/", VarselWeb do
    pipe_through :browser

    get "/", PageController, :home
    get "/scope", PageController, :page, assigns: %{page_id: "scope"}
    get "/contact", PageController, :page, assigns: %{page_id: "contact"}
    get "/cve-criteria", PageController, :page, assigns: %{page_id: "cve-criteria"}
    get "/security-policy", PageController, :page, assigns: %{page_id: "security-policy"}
    get "/data-licensing", PageController, :page, assigns: %{page_id: "data-licensing"}
    get "/coordinator-process", PageController, :page, assigns: %{page_id: "coordinator-process"}
    get "/maintainer-process", PageController, :page, assigns: %{page_id: "maintainer-process"}
    live "/common-weaknesses", CommonWeaknessesLive, :index

    # POC-only admin tooling (loads current_user + gates on the POC role).
    # Registered before the public `/cves` scope so `/cves/manage` wins over
    # `/cves/:cve_id`.
    ash_authentication_live_session :poc_required,
      on_mount: [{VarselWeb.LiveUserAuth, :live_poc_required}] do
      live "/users", UserManagementLive, :index
      live "/cves/manage", VarselLive, :index
      live "/cves/manage/:id", VarselEditLive, :edit
    end

    # Any logged-in user may report a vulnerability and manage their own tokens.
    # Cases are visible to POCs and assigned supporters (policies scope reads).
    ash_authentication_live_session :authenticated,
      on_mount: [{VarselWeb.LiveUserAuth, :live_user_required}] do
      live "/report", VulnerabilityReportLive, :new
      live "/settings/tokens", ApiKeySettingsLive, :index
      live "/cases", CaseManagementLive, :index
      live "/cases/:id", CaseDetailLive, :show
    end
  end

  # Authentication pages — bare, centered layout (no site nav/footer).
  scope "/", VarselWeb do
    pipe_through :auth_browser

    auth_routes AuthController, User, path: "/auth"
    sign_out_route AuthController

    # Remove these if you'd like to use your own authentication views
    sign_in_route register_path: "/register",
                  reset_path: "/reset",
                  auth_routes_prefix: "/auth",
                  on_mount: [{VarselWeb.LiveUserAuth, :live_no_user}],
                  overrides: [
                    VarselWeb.AuthOverrides,
                    DaisyUI
                  ]

    # Remove this if you do not want to use the reset password feature
    reset_route auth_routes_prefix: "/auth",
                overrides: [
                  VarselWeb.AuthOverrides,
                  DaisyUI
                ]

    # Remove this if you do not use the confirmation strategy
    confirm_route User, :confirm_new_user,
      auth_routes_prefix: "/auth",
      overrides: [
        VarselWeb.AuthOverrides,
        DaisyUI
      ]

    # Remove this if you do not use the magic link strategy.
    magic_sign_in_route(User, :magic_link,
      auth_routes_prefix: "/auth",
      overrides: [
        VarselWeb.AuthOverrides,
        DaisyUI
      ]
    )
  end

  scope "/mcp" do
    pipe_through :mcp

    forward "/", AshAi.Mcp.Router,
      tools: [
        :list_weaknesses,
        :get_weakness,
        :search_weaknesses,
        :list_attack_patterns,
        :get_attack_pattern,
        :search_attack_patterns,
        :list_cves,
        :get_cve,
        :search_cves,
        :list_cves_by_purl,
        :validate_cve_record,
        :validate_cve_record_schema,
        :validate_cve_record_cvelint,
        :validate_cve_record_hex_packages,
        :list_osv_records,
        :get_osv_record,
        :submit_vulnerability_report,
        :list_all_cves,
        :available_cve_ids,
        :assign_cve,
        :update_cve,
        :request_publish_cve,
        :reject_cve,
        :list_users,
        :update_user,
        :set_user_role,
        :list_cases,
        :get_case,
        :render_case_preview,
        :refresh_case_derivation,
        :list_case_proposals,
        :list_open_case_proposals,
        :create_case_proposal,
        :withdraw_case_proposal,
        :list_case_comments,
        :create_case_comment
      ],
      otp_app: :varsel
  end

  # Public HTML surface (browser pipeline: session, root layout, navbar).
  scope "/", VarselWeb do
    pipe_through :browser

    live "/cves", CveListLive, :index
    # HTML detail. `.json` requests fall through to the JSON scope below since
    # this matches a single non-".json" segment.
    get "/cves/:cve_id", CveController, :show_html

    get "/feed.atom", FeedController, :atom
    get "/feed.rss", FeedController, :rss

    # OSV vulnerability id -> CVE detail page (mirrors the Jekyll redirect).
    get "/osv/:osv_id", OsvController, :redirect_to_cve
  end

  # Machine-readable JSON API (kept on its own pipeline).
  scope "/cves", VarselWeb do
    pipe_through :api

    get "/index.json", CveController, :index
    get "/*path", CveController, :show_json
  end

  scope "/osv", VarselWeb do
    pipe_through :api

    get "/all.json", OsvController, :index
    get "/*path", OsvController, :show
  end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:varsel, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import AshAdmin.Router
    import Oban.Web.Router
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: VarselWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview

      oban_dashboard("/oban")

      ash_admin "/admin"
    end
  end
end
