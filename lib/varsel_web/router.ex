# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Router do
  use VarselWeb, :router
  use AshAuthentication.Phoenix.Router
  use AshAuthentication.Phoenix.Oauth2Server.Router

  alias Elixir.AshAuthentication.Phoenix.Overrides.DaisyUI
  alias Varsel.Accounts.User
  alias VarselWeb.Plugs.ApiKeyAuth
  alias VarselWeb.Plugs.HexServiceAuth
  alias VarselWeb.Plugs.OauthBearerAuth
  alias VarselWeb.Plugs.PublicResource

  @nav_user_load VarselWeb.Layouts.nav_user_load()

  # Accepts an `eefcna_` API key, an AshAuthentication session JWT, or an
  # OAuth 2.1 access token; anonymous requests get the 401 challenge.
  pipeline :graphql do
    plug ApiKeyAuth
    plug :load_from_bearer
    plug :set_actor, :user
    plug OauthBearerAuth, oauth2_server: Varsel.Oauth2Server, scope: "gql"
    plug AshGraphql.Plug
  end

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {VarselWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :load_from_session, load: @nav_user_load
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
    plug :load_from_session, load: @nav_user_load
    # Tells the OAuth callback's register action that this sign-in is a link.
    plug VarselWeb.Plugs.OauthLinking
    # Parks ?return_to= in the session, which survives the trip to the OAuth
    # provider and back; AuthController.success/4 spends it.
    plug VarselWeb.Plugs.ReturnPath
  end

  # Pages that only mean anything for a signed-in user; anonymous callers are
  # sent to sign in rather than shown an empty version.
  pipeline :logged_in_browser do
    plug VarselWeb.Plugs.RequireLogin
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

  # hex.pm's report intake. Authenticated as a system rather than a person,
  # so no actor is set and the routes behind it carry no user identity.
  pipeline :hex_intake do
    plug :accepts, ["json"]
    plug HexServiceAuth
  end

  scope "/gql" do
    pipe_through [:graphql]

    # Irrelevant: compile time, not runtime.
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    forward "/", Absinthe.Plug, schema: Module.concat(["VarselWeb.GraphqlSchema"])
  end

  scope "/", VarselWeb do
    pipe_through :browser

    get "/", PageController, :home

    # Content pages moved from the old Jekyll site's `<page>.html` URLs to the
    # nicer extensionless form. The clean path is canonical (200); the old
    # `.html` path 301-redirects to it so existing links don't break.
    for {path, page_id} <- [
          {"/scope", "scope"},
          {"/contact", "contact"},
          {"/cve-criteria", "cve-criteria"},
          {"/security-policy", "security-policy"},
          {"/data-licensing", "data-licensing"},
          {"/api-access", "api-access"},
          {"/coordinator-process", "coordinator-process"},
          {"/maintainer-process", "maintainer-process"}
          # TODO: Re-enable once the privacy policy and terms are approved.
          # {"/privacy-policy", "privacy-policy"},
          # {"/terms-and-conditions", "terms-and-conditions"}
        ] do
      get path, PageController, :page, assigns: %{page_id: page_id}
      get "#{path}.html", PageController, :legacy_redirect, assigns: %{to: path}
    end

    # The Varsel guide postdates the Jekyll site, so no legacy redirects.
    for {path, page_id} <- [
          {"/guide", "guide"},
          {"/guide/filing-a-case", "guide-filing-a-case"},
          {"/guide/review-and-publication", "guide-review-and-publication"},
          {"/guide/affected-versions", "guide-affected-versions"},
          {"/guide/record-conventions", "guide-record-conventions"},
          {"/guide/ai-tooling", "guide-ai-tooling"}
        ] do
      get path, PageController, :page, assigns: %{page_id: page_id}
    end

    # The old site's directory index and home `.html`.
    get "/data-licensing/index.html", PageController, :legacy_redirect, assigns: %{to: "/data-licensing"}

    get "/index.html", PageController, :legacy_redirect, assigns: %{to: "/"}

    get "/common-weaknesses", CommonWeaknessesController, :index
    get "/common-weaknesses/:view_id", CommonWeaknessesController, :view
    get "/common-weaknesses/:view_id/:cwe_id", CommonWeaknessesController, :show

    get "/common-weaknesses.html", PageController, :legacy_redirect, assigns: %{to: "/common-weaknesses"}

    ash_authentication_live_session :auth,
      on_mount: [
        {VarselWeb.LiveUserAuth, :live_user},
        {VarselWeb.LiveNotifications, :default},
        {VarselWeb.LiveCurrentPath, :default}
      ] do
      live "/cves", CveListLive, :index
      live "/cves/manage/:id", VarselEditLive, :edit

      live "/report", VulnerabilityReportLive, :new
      live "/reports", ReportTriageLive, :index

      live "/cases", CaseManagementLive, :index
      live "/cases/:id", CaseDetailLive, :view
      live "/cases/:id/edit", CaseDetailLive, :edit
      live "/cases/:id/propose", CaseDetailLive, :propose
      live "/cases/:id/cve", CaseRecordLive, :cve
      live "/cases/:id/osv", CaseRecordLive, :osv
      live "/cases/:id/publication", CaseRecordLive, :publication

      live "/users", UserManagementLive, :index
      live "/settings/account", AccountSettingsLive, :index
      live "/settings/tokens", ApiKeySettingsLive, :index
      live "/settings/notifications", NotificationSettingsLive, :index

      live "/notifications", NotificationsLive, :index
    end
  end

  # Linking a second provider to the account you are already signed in as.
  # Only the confirmation step is a page; the rest is redirects around the
  # ordinary OAuth flow (see VarselWeb.AccountLinkController).
  scope "/settings/account/link", VarselWeb do
    pipe_through [:browser, :logged_in_browser]

    get "/start/:strategy", AccountLinkController, :start
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
        :get_weakness_related_weaknesses,
        :get_weakness_related_attack_patterns,
        :search_weaknesses,
        :list_attack_patterns,
        :get_attack_pattern,
        :get_attack_pattern_relations,
        :search_attack_patterns,
        :list_cves,
        :get_cve,
        :validate_cve,
        :search_cves,
        :list_cves_by_purl,
        :validate_cve_record,
        :validate_cve_record_schema,
        :validate_cve_record_cvelint,
        :validate_cve_record_hex_packages,
        :validate_cve_record_eef,
        :list_osv_records,
        :get_osv_record,
        :submit_vulnerability_report,
        :list_all_cves,
        :available_cve_ids,
        :assign_cve,
        :withhold_cve,
        :update_cve,
        :request_publish_cve,
        :reject_cve,
        :list_users,
        :update_user,
        :set_user_role,
        :open_case,
        :list_cases,
        :get_case,
        :render_case_preview,
        :validate_case,
        :refresh_case_derivation,
        :list_case_proposals,
        :list_open_case_proposals,
        :get_case_proposal,
        :propose_title,
        :propose_description,
        :propose_workarounds,
        :propose_configurations,
        :propose_solutions,
        :propose_internal_notes,
        :propose_discovery,
        :propose_cvss,
        :propose_date_public,
        :propose_timeline,
        :propose_cna_override,
        :propose_weakness,
        :propose_impact,
        :propose_reference,
        :propose_credit,
        :propose_affected_package,
        :propose_otp_affected_package,
        :propose_elixir_affected_package,
        :propose_gleam_affected_package,
        :propose_package_channel,
        :propose_version_event,
        :propose_delete,
        :withdraw_case_proposal,
        :list_case_comments,
        :grant_case_access
      ],
      otp_app: :varsel
  end

  # Machine-readable JSON API (kept on its own pipeline).
  scope "/cves", VarselWeb do
    pipe_through :api

    get "/index.json", CveController, :index
  end

  scope "/osv", VarselWeb do
    pipe_through :api

    get "/all.json", OsvController, :index
  end

  # hex.pm forwards package reports here. The service token is the whole of
  # the authorization: no actor is resolved, and nothing else may join this
  # pipeline.
  scope "/api/hex", VarselWeb do
    pipe_through :hex_intake

    post "/reports", HexReportController, :create
  end

  # Public HTML surface (browser pipeline: session, root layout, navbar).
  scope "/", VarselWeb do
    pipe_through :browser

    # Both OSV and CVE render based on the path extension (.json / .html)
    # check their respective controllers for detailed routing.
    get "/osv/:osv_id", OsvController, :show
    get "/cves/:cve_id", CveController, :show

    get "/feed.atom", FeedController, :atom
    get "/feed.rss", FeedController, :rss
    get "/sitemap.xml", SitemapController, :index
  end

  # The developer tooling (storybook, Oban Web, LiveDashboard, AshAdmin, the
  # mailbox and error-page previews) lives in VarselWeb.DevRouter, under
  # `dev/` — a directory only compiled for :dev and :test, which is what keeps
  # it out of production.
  #
  # Forwarded at the root rather than at "/dev": several of those tools build
  # their own redirects from the path they were mounted at and cannot see a
  # forward's prefix, so they declare their own full `/dev/...` paths instead.
  # Registered last so every route above still wins.
  if Mix.env() in [:dev, :test] do
    forward "/", VarselWeb.DevRouter
  end
end
