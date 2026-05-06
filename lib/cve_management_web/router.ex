# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.Router do
  use CveManagementWeb, :router
  use AshAuthentication.Phoenix.Router

  import AshAuthentication.Plug.Helpers

  alias CveManagement.Accounts.User
  alias Elixir.AshAuthentication.Phoenix.Overrides.DaisyUI

  pipeline :graphql do
    plug AshGraphql.Plug
  end

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {CveManagementWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :load_from_session
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug :load_from_bearer
    plug :set_actor, :user
  end

  scope "/gql" do
    pipe_through [:graphql]

    forward "/playground", Absinthe.Plug.GraphiQL,
      schema: Module.concat(["CveManagementWeb.GraphqlSchema"]),
      socket: Module.concat(["CveManagementWeb.GraphqlSocket"]),
      interface: :simple

    forward "/", Absinthe.Plug, schema: Module.concat(["CveManagementWeb.GraphqlSchema"])
  end

  scope "/", CveManagementWeb do
    pipe_through :browser

    get "/auth/github_app", GitHubAppController, :authorize
    get "/auth/github_app/callback", GitHubAppController, :callback

    ash_authentication_live_session :authenticated_routes,
      on_mount: [{CveManagementWeb.LiveUserAuth, :live_user_required}] do
      # in each liveview, add one of the following at the top of the module:
      #
      # If an authenticated user must be present:
      # on_mount {CveManagementWeb.LiveUserAuth, :live_user_required}
      #
      # If an authenticated user *may* be present:
      # on_mount {CveManagementWeb.LiveUserAuth, :live_user_optional}
      #
      # If an authenticated user must *not* be present:
      # on_mount {CveManagementWeb.LiveUserAuth, :live_no_user}
      live "/settings", SettingsLive
    end

    get "/", PageController, :home
    get "/scope", PageController, :page, assigns: %{page_id: "scope"}
    get "/contact", PageController, :page, assigns: %{page_id: "contact"}
    get "/cve-criteria", PageController, :page, assigns: %{page_id: "cve-criteria"}
    get "/security-policy", PageController, :page, assigns: %{page_id: "security-policy"}
    auth_routes AuthController, User, path: "/auth"
    sign_out_route AuthController

    # Remove these if you'd like to use your own authentication views
    sign_in_route register_path: "/register",
                  reset_path: "/reset",
                  auth_routes_prefix: "/auth",
                  on_mount: [{CveManagementWeb.LiveUserAuth, :live_no_user}],
                  overrides: [
                    CveManagementWeb.AuthOverrides,
                    DaisyUI
                  ]

    # Remove this if you do not want to use the reset password feature
    reset_route auth_routes_prefix: "/auth",
                overrides: [
                  CveManagementWeb.AuthOverrides,
                  DaisyUI
                ]

    # Remove this if you do not use the confirmation strategy
    confirm_route User, :confirm_new_user,
      auth_routes_prefix: "/auth",
      overrides: [
        CveManagementWeb.AuthOverrides,
        DaisyUI
      ]

    # Remove this if you do not use the magic link strategy.
    magic_sign_in_route(User, :magic_link,
      auth_routes_prefix: "/auth",
      overrides: [
        CveManagementWeb.AuthOverrides,
        DaisyUI
      ]
    )
  end

  scope "/mcp" do
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
        :list_cves_by_purl
      ],
      otp_app: :cve_management
  end

  scope "/cves", CveManagementWeb do
    pipe_through :api

    get "/index.json", CveController, :index
    get "/*path", CveController, :show
  end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:cve_management, :dev_routes) do
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

      live_dashboard "/dashboard", metrics: CveManagementWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview

      oban_dashboard("/oban")

      ash_admin "/admin"
    end
  end
end
