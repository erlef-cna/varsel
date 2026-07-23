# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Router do
  use VarselWeb, :router
  use AshAuthentication.Phoenix.Router
  use AshAuthentication.Phoenix.Oauth2Server.Router

  alias Elixir.AshAuthentication.Phoenix.Overrides.DaisyUI
  alias Varsel.Accounts.User
  alias VarselWeb.Plugs.ApiKeyAuth
  alias VarselWeb.Plugs.OauthBearerAuth
  alias VarselWeb.Plugs.PublicResource

  # Accepts an `eefcna_` API key, an AshAuthentication session JWT, or an
  # OAuth 2.1 access token; anonymous requests get the 401 challenge.
  pipeline :graphql do
    plug ApiKeyAuth
    plug :load_from_bearer
    plug :set_actor, :user
    plug OauthBearerAuth, oauth2_server: Varsel.Oauth2Server, scope: "gql"
    plug AshGraphql.Plug
  end

  # The GraphiQL playground authenticates through the browser session
  # instead of a bearer token. No CSRF protection (GraphiQL posts carry no
  # token); cross-site POSTs are covered by the SameSite=Lax session cookie.
  pipeline :graphql_playground do
    plug :fetch_session
    plug :load_from_session
    plug :set_actor, :user
    plug :require_login
    # The bundled GraphiQL page (login-gated dev/POC debugging tool) loads
    # React/GraphiQL from cdn.jsdelivr.net and relies on inline <script>/<style>,
    # none of which the app-wide strict CSP permits. Re-run the CSP plug with a
    # policy scoped just to what GraphiQL needs; its header replaces the
    # endpoint's for this route only, leaving the rest of the site deny-by-default.
    # nonces_for: [] overrides the app-level default (which nonces script_src);
    # a script nonce here would make browsers ignore the 'unsafe-inline' that
    # GraphiQL's inline bootstrap script depends on.
    plug PlugContentSecurityPolicy,
      nonces_for: [],
      directives: %{
        default_src: ~w('self' https://cdn.jsdelivr.net),
        script_src: ~w('self' 'unsafe-inline' https://cdn.jsdelivr.net),
        style_src: ~w('self' 'unsafe-inline' https://cdn.jsdelivr.net),
        img_src: ~w('self' data: https://cdn.jsdelivr.net),
        font_src: ~w('self' data: https://cdn.jsdelivr.net),
        # jsdelivr for the sourcemap (.map) fetches devtools makes; 'self' for
        # GraphiQL's same-origin WebSocket back to the app.
        connect_src: ~w('self' https://cdn.jsdelivr.net),
        base_uri: ~w('none'),
        object_src: ~w('none')
      }

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
    # The OAuth consent screen identifies the consenting user through the
    # conn's Ash actor (Ash.PlugHelpers.get_actor/1).
    plug :set_actor, :user
    # `/cves/<id>.json`, `/osv/*.json` and the Atom/RSS feeds are served on this
    # pipeline (the `.json` id delegates within the HTML detail action). Drop
    # CORP for those JSON/feed responses so they stay fetchable cross-origin;
    # HTML pages keep the default same-site policy (content-type gated).
    plug PublicResource
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
    # Public JSON data — drop CORP so it can be fetched cross-origin.
    plug PublicResource
  end

  # MCP tool calls read the actor from the conn (Ash.PlugHelpers). Access
  # requires a login: either an `eefcna_` API key or an OAuth 2.1 access
  # token; anonymous requests get the 401 discovery challenge.
  pipeline :mcp do
    plug ApiKeyAuth
    plug OauthBearerAuth, oauth2_server: Varsel.Oauth2Server, scope: "mcp"
  end

  # Client-facing OAuth 2.1 protocol endpoints (token, DCR, discovery
  # metadata) — called by external OAuth clients, so no session/CSRF.
  pipeline :oauth_protocol do
    plug :accepts, ["json"]
  end

  # The bundled dev dashboards (LiveDashboard, Oban Web, AshAdmin, Swoosh
  # mailbox) all rely on inline scripts/styles and eval that the app-wide
  # strict CSP forbids. They only mount under the `:dev_routes` compile flag
  # (never in production), so replace the strict header with Phoenix's own
  # secure-browser default (`base-uri 'self'; frame-ancestors 'self'`) — enough
  # to keep clickjacking/base-tag protections without constraining these tools.
  pipeline :dev_tools_relaxed_csp do
    plug PlugContentSecurityPolicy,
      nonces_for: [],
      directives: %{
        base_uri: ~w('self'),
        frame_ancestors: ~w('self')
      }
  end

  scope "/gql" do
    pipe_through [:graphql_playground]

    # These Module.concat/1 calls take fixed compile-time module-name literals
    # for modules that always exist, so they carry no runtime atom-exhaustion
    # risk; safe_concat would only add a needless preload requirement.
    forward "/playground", Absinthe.Plug.GraphiQL,
      # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
      schema: Module.concat(["VarselWeb.GraphqlSchema"]),
      # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
      socket: Module.concat(["VarselWeb.GraphqlSocket"]),
      interface: :simple
  end

  scope "/gql" do
    pipe_through [:graphql]

    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
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
    get "/api-access", PageController, :page, assigns: %{page_id: "api-access"}
    get "/coordinator-process", PageController, :page, assigns: %{page_id: "coordinator-process"}
    get "/maintainer-process", PageController, :page, assigns: %{page_id: "maintainer-process"}
    live "/common-weaknesses", CommonWeaknessesLive, :index

    # POC-only admin tooling (loads current_user + gates on the POC role).
    # Registered before the public `/cves` scope so `/cves/manage/:id` wins
    # over `/cves/:cve_id`.
    ash_authentication_live_session :poc_required,
      on_mount: [
        {VarselWeb.LiveUserAuth, :live_poc_required},
        {VarselWeb.LiveNotifications, :default}
      ] do
      live "/users", UserManagementLive, :index
      live "/cves/manage/:id", VarselEditLive, :edit
      live "/reports", ReportTriageLive, :index
    end

    # Public pages that adapt to a signed-in user: the CVE list doubles as
    # the POC's management console.
    # The management list merged into /cves; keep old bookmarks working.
    get "/cves/manage", PageController, :manage_redirect

    # Public pages that adapt to a signed-in user: the CVE list doubles as
    # the POC's management console.
    ash_authentication_live_session :user_optional,
      on_mount: [
        {VarselWeb.LiveUserAuth, :live_user_optional},
        {VarselWeb.LiveNotifications, :default}
      ] do
      live "/cves", CveListLive, :index
    end

    # Any logged-in user may report a vulnerability and manage their own tokens.
    # Cases are visible to POCs and assigned supporters (policies scope reads).
    ash_authentication_live_session :authenticated,
      on_mount: [
        {VarselWeb.LiveUserAuth, :live_user_required},
        {VarselWeb.LiveNotifications, :default}
      ] do
      live "/report", VulnerabilityReportLive, :new
      live "/settings/tokens", ApiKeySettingsLive, :index
      live "/cases", CaseManagementLive, :index
      live "/cases/:id", CaseDetailLive, :view
      live "/cases/:id/edit", CaseDetailLive, :edit
      live "/cases/:id/propose", CaseDetailLive, :propose
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

  # OAuth 2.1 authorization server (used by MCP clients): user-facing
  # consent screen plus client-facing protocol/discovery endpoints.
  scope "/" do
    pipe_through :browser

    oauth2_server_consent_routes(oauth2_server: Varsel.Oauth2Server)
  end

  scope "/" do
    pipe_through :oauth_protocol

    oauth2_server_protocol_routes(oauth2_server: Varsel.Oauth2Server)
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

  defp require_login(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> redirect(to: "/sign-in")
      |> halt()
    end
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
      pipe_through [:browser, :dev_tools_relaxed_csp]

      live_dashboard "/dashboard", metrics: VarselWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview

      oban_dashboard("/oban")

      ash_admin "/admin"
    end
  end
end
