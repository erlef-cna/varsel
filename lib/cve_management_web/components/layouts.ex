# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.
  """
  use CveManagementWeb, :html

  # Embed all files in layouts/* within this module.
  # The default root.html.heex file contains the HTML
  # skeleton of your application, namely HTML headers
  # and other static content.
  embed_templates "layouts/*"

  @doc """
  Renders your app layout.

  This function is typically invoked from every template,
  and it often contains your application menu, sidebar,
  or similar.

  ## Examples

      <Layouts.app flash={@flash}>
        <h1>Content</h1>
      </Layouts.app>

  """
  attr :flash, :map, required: true, doc: "the map of flash messages"

  attr :current_scope, :map,
    default: nil,
    doc: "the current [scope](https://hexdocs.pm/phoenix/scopes.html)"

  slot :inner_block, required: true

  def app(assigns) do
    ~H"""
    <main class="px-4 py-10 sm:px-6 lg:px-8">
      <div class="mx-auto max-w-4xl space-y-4">
        {render_slot(@inner_block)}
      </div>
    </main>

    <.flash_group flash={@flash} />
    """
  end

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />

      <.flash
        id="client-error"
        kind={:error}
        title={gettext("We can't find the internet")}
        phx-disconnected={show(".phx-client-error #client-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#client-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title={gettext("Something went wrong!")}
        phx-disconnected={show(".phx-server-error #server-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#server-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>
    </div>
    """
  end

  @eef_logo_svg File.read!(Path.join([__DIR__, "..", "..", "..", "assets", "svg", "eef-header-logo.svg"]))
  @external_resource Path.join([
                       __DIR__,
                       "..",
                       "..",
                       "..",
                       "assets",
                       "svg",
                       "eef-header-logo.svg"
                     ])

  @doc """
  The EEF wordmark, read from `assets/svg/eef-header-logo.svg` at compile time
  and inlined so it inherits `currentColor` (white in the navy bands, brand
  navy elsewhere). Wrap in a sized element via `class`.

  The SVG's internal `clipPath` id is rewritten per instance so the logo can be
  rendered more than once on a page without producing duplicate DOM ids.
  """
  attr :class, :string, default: "h-6"
  attr :id, :string, default: "eef-logo", doc: "unique base for the internal clip id"

  def eef_logo(assigns) do
    svg =
      @eef_logo_svg
      |> String.replace(~s(id="a"), ~s(id="#{assigns.id}-clip"))
      |> String.replace("url(#a)", "url(##{assigns.id}-clip)")

    assigns = assign(assigns, :svg, {:safe, svg})

    ~H"""
    <span
      class={["eef-logo inline-flex items-center", @class]}
      aria-label="Erlang Ecosystem Foundation"
      role="img"
    >
      {@svg}
    </span>
    """
  end

  @doc "Primary site navigation bar."
  attr :current_user, :any, default: nil

  def site_nav(assigns) do
    ~H"""
    <header class="eef-band border-b border-white/10 sticky top-0 z-40">
      <nav class="container mx-auto px-4 sm:px-6 lg:px-8 flex items-center gap-4 h-16">
        <a
          href="/"
          class="eef-band-plain flex items-center gap-3 shrink-0 text-white hover:opacity-80 transition-opacity"
        >
          <.eef_logo class="h-7" id="eef-logo-nav" />
          <span class="font-semibold text-white/80 border-l border-white/20 pl-3 hidden sm:block">
            CNA
          </span>
        </a>

        <%!-- Desktop menu --%>
        <ul class="hidden md:flex items-center gap-1 ml-2 text-sm text-white">
          <li>
            <a
              href={~p"/cves"}
              class="eef-band-plain px-3 py-2 rounded hover:bg-white/10 transition-colors block"
            >
              CVEs
            </a>
          </li>
          <li>
            <a
              href={~p"/common-weaknesses"}
              class="eef-band-plain px-3 py-2 rounded hover:bg-white/10 transition-colors block"
            >
              Weaknesses
            </a>
          </li>
          <li class="group relative">
            <button class="px-3 py-2 rounded hover:bg-white/10 transition-colors flex items-center gap-1">
              Documentation <.icon name="hero-chevron-down-micro" class="size-3.5" />
            </button>
            <div class="invisible opacity-0 group-hover:visible group-hover:opacity-100 transition-opacity absolute left-0 top-full pt-1 w-60">
              <ul class="bg-base-100 text-base-content rounded-box shadow-lg border border-base-300 p-2 space-y-0.5">
                <li :for={{label, path} <- doc_links()}>
                  <a href={path} class="block px-3 py-1.5 rounded hover:bg-base-200 transition-colors">
                    {label}
                  </a>
                </li>
              </ul>
            </div>
          </li>
          <li :if={poc?(@current_user)}>
            <a
              href={~p"/users"}
              class="eef-band-plain px-3 py-2 rounded hover:bg-white/10 transition-colors block"
            >
              Users
            </a>
          </li>
        </ul>

        <div class="ml-auto flex items-center gap-2">
          <.theme_toggle />
          <span
            :if={@current_user}
            class="text-sm text-white/70 hidden lg:block max-w-[12rem] truncate"
          >
            {@current_user.name || @current_user.email}
          </span>
          <a
            :if={@current_user}
            href="/sign-out"
            data-method="delete"
            class="btn btn-ghost btn-sm text-white hover:bg-white/10"
          >
            Sign out
          </a>
          <a :if={is_nil(@current_user)} href="/sign-in" class="btn btn-primary btn-sm">Login</a>

          <%!-- Mobile menu --%>
          <div class="dropdown dropdown-end md:hidden">
            <div tabindex="0" role="button" class="btn btn-ghost btn-sm text-white hover:bg-white/10">
              <.icon name="hero-bars-3" class="size-5" />
            </div>
            <ul
              tabindex="0"
              class="dropdown-content menu bg-base-100 text-base-content rounded-box shadow-lg border border-base-300 mt-2 w-60 p-2 z-50"
            >
              <li><a href={~p"/cves"}>CVEs</a></li>
              <li><a href={~p"/common-weaknesses"}>Weaknesses</a></li>
              <li class="menu-title mt-1">Documentation</li>
              <li :for={{label, path} <- doc_links()}><a href={path}>{label}</a></li>
            </ul>
          </div>
        </div>
      </nav>
    </header>
    """
  end

  @doc "Site footer with EEF navy band."
  def site_footer(assigns) do
    ~H"""
    <footer class="eef-band mt-16">
      <div class="container mx-auto px-4 sm:px-6 lg:px-8 py-12 grid grid-cols-2 md:grid-cols-4 gap-8 text-sm">
        <div class="col-span-2 md:col-span-1">
          <div class="flex items-center gap-3 mb-3 text-white">
            <.eef_logo class="h-8" id="eef-logo-footer" />
            <span class="font-semibold text-white/80 border-l border-white/20 pl-3">CNA</span>
          </div>
          <p class="text-white/60 leading-relaxed">
            The Erlang Ecosystem Foundation's CVE Numbering Authority for the BEAM ecosystem.
          </p>
        </div>

        <div>
          <p class="eef-eyebrow mb-3">Records</p>
          <ul class="space-y-2">
            <li><a href={~p"/cves"}>All CVEs</a></li>
            <li><a href={~p"/common-weaknesses"}>Common Weaknesses</a></li>
            <li><a href={~p"/cves/index.json"}>CVE index (JSON)</a></li>
            <li><a href={~p"/osv/all.json"}>OSV feed (JSON)</a></li>
          </ul>
        </div>

        <div>
          <p class="eef-eyebrow mb-3">Process</p>
          <ul class="space-y-2">
            <li><a href={~p"/scope"}>Scope</a></li>
            <li><a href={~p"/cve-criteria"}>CVE Criteria</a></li>
            <li><a href={~p"/maintainer-process"}>Maintainer Process</a></li>
            <li><a href={~p"/coordinator-process"}>Coordinator Process</a></li>
          </ul>
        </div>

        <div>
          <p class="eef-eyebrow mb-3">More</p>
          <ul class="space-y-2">
            <li><a href={~p"/contact"}>Contact</a></li>
            <li><a href={~p"/security-policy"}>Security Policy</a></li>
            <li><a href={~p"/data-licensing"}>Data Licensing</a></li>
            <li><a href="https://erlef.org/" target="_blank" rel="noopener">erlef.org</a></li>
          </ul>
        </div>
      </div>
      <div class="border-t border-white/10">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8 py-4 text-xs text-white/50">
          © {Date.utc_today().year} Erlang Ecosystem Foundation. CVE data licensed <a href={
            ~p"/data-licensing"
          }>CC-BY 4.0</a>.
        </div>
      </div>
    </footer>
    """
  end

  defp doc_links do
    [
      {"Scope", "/scope"},
      {"CVE Criteria", "/cve-criteria"},
      {"Security Policy", "/security-policy"},
      {"Maintainer Process", "/maintainer-process"},
      {"Coordinator Process", "/coordinator-process"},
      {"Data Licensing", "/data-licensing"},
      {"Contact", "/contact"}
    ]
  end

  defp poc?(%{role: :poc}), do: true
  defp poc?(_user), do: false

  @doc """
  Provides dark vs light theme toggle based on themes defined in app.css.

  See <head> in root.html.heex which applies the theme before page load.
  """
  def theme_toggle(assigns) do
    ~H"""
    <%!-- Lives in the navy nav band in both themes, so it uses fixed white-on-navy
         colors rather than theme-relative base tokens. --%>
    <div class="relative flex flex-row items-center rounded-full border border-white/20 bg-white/10">
      <div class="absolute w-1/3 h-full rounded-full bg-white/25 left-0 [[data-theme=light]_&]:left-1/3 [[data-theme=dark]_&]:left-2/3 transition-[left]" />

      <button
        class="relative flex p-2 cursor-pointer w-1/3 text-white"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="system"
        aria-label="Use system theme"
      >
        <.icon name="hero-computer-desktop-micro" class="size-4 opacity-70 hover:opacity-100" />
      </button>

      <button
        class="relative flex p-2 cursor-pointer w-1/3 text-white"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="light"
        aria-label="Use light theme"
      >
        <.icon name="hero-sun-micro" class="size-4 opacity-70 hover:opacity-100" />
      </button>

      <button
        class="relative flex p-2 cursor-pointer w-1/3 text-white"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="dark"
        aria-label="Use dark theme"
      >
        <.icon name="hero-moon-micro" class="size-4 opacity-70 hover:opacity-100" />
      </button>
    </div>
    """
  end
end
