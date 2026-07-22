// SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
//
// SPDX-License-Identifier: Apache-2.0

// If you want to use Phoenix channels, run `mix help phx.gen.channel`
// to get started and then uncomment the line below.
// import "./user_socket.js"

// You can include dependencies in two ways.
//
// The simplest option is to put them in assets/vendor and
// import them using relative paths:
//
//     import "../vendor/some-package.js"
//
// Alternatively, you can `npm install some-package --prefix assets` and import
// them using a path starting with the package name:
//
//     import "some-package"
//
// If you have dependencies that try to import CSS, esbuild will generate a separate `app.css` file.
// To load it, simply add a second `<link>` to your `root.html.heex` file.

// Include phoenix_html to handle method=PUT/DELETE in forms and buttons.
import "phoenix_html"
// Establish Phoenix Socket and LiveView configuration.
import {Socket} from "phoenix"
import {LiveSocket} from "phoenix_live_view"
import {hooks as colocatedHooks} from "phoenix-colocated/varsel"
import topbar from "../vendor/topbar"
import Sortable from "sortablejs"

// Drag & drop list reordering: sorts the container's [data-drag-id] children
// via Sortable.js and pushes the container's data-sort-event with the ids in
// their new order once a drag finishes.
const DragSort = {
  mounted() {
    this.sortable = new Sortable(this.el, {
      animation: 150,
      draggable: "[data-drag-id]",
      handle: "[data-drag-handle]",
      ghostClass: "opacity-50",
      onEnd: () => {
        const ids = [...this.el.querySelectorAll("[data-drag-id]")].map((el) => el.dataset.dragId)
        this.pushEvent(this.el.dataset.sortEvent, {ids})
      },
    })
  },
  destroyed() {
    this.sortable?.destroy()
  },
}

// Workspace section rail. Two jobs:
//
// 1. Anchor navigation: on LiveView pages Chromium cancels the smooth
//    fragment-scroll animation (html { scroll-behavior: smooth }) as soon as
//    LiveView's scroll bookkeeping calls history.replaceState, so a native
//    hash click updates the URL without moving the page. Same-page anchor
//    clicks are therefore handled here with an instant scrollIntoView (which
//    honors scroll-margin) — document-wide, so "Jump" links and the preview
//    slide-over's "Go to <section>" blocker links get the same treatment.
// 2. Scroll spy: the rail entry whose section sits nearest above the viewport
//    top gets the .is-active class (styled in app.css).
const SectionRail = {
  mounted() {
    this.onClick = (e) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
      const link = e.target.closest && e.target.closest('a[href^="#"]')
      if (!link) return
      const target = document.getElementById(decodeURIComponent(link.getAttribute("href").slice(1)))
      if (!target) return
      e.preventDefault()
      target.scrollIntoView({behavior: "instant", block: "start"})
      history.pushState(history.state, "", link.getAttribute("href"))
    }
    document.addEventListener("click", this.onClick)
    this.onScroll = () => {
      if (this.raf) return
      this.raf = requestAnimationFrame(() => {
        this.raf = null
        this.spy()
      })
    }
    window.addEventListener("scroll", this.onScroll, {passive: true})
    this.spy()
  },
  // LiveView patches rewrite the class attribute; re-mark after each patch.
  updated() {
    this.spy()
  },
  destroyed() {
    document.removeEventListener("click", this.onClick)
    window.removeEventListener("scroll", this.onScroll)
    if (this.raf) cancelAnimationFrame(this.raf)
  },
  links() {
    return [...this.el.querySelectorAll('a[href^="#"]')]
  },
  spy() {
    // Sticky navbar (4rem) + the 5.5rem scroll-margin headroom.
    const offset = 96
    const links = this.links()
    let active = null
    for (const link of links) {
      const target = document.getElementById(link.getAttribute("href").slice(1))
      if (target && target.getBoundingClientRect().top <= offset) active = link
    }
    active = active || links[0]
    links.forEach((link) => link.classList.toggle("is-active", link === active))
  },
}

// Plain-JS ToC scroll-spy for controller-rendered (dead) pages — the public
// CVE detail page and the docs page template — where no LiveView hook runs.
// Marks the entry whose section sits nearest above the viewport top with
// .is-active (styled in app.css), mirroring the SectionRail hook's spy/2
// semantics for the workspace rail without any of its LiveView lifecycle.
function initTocScrollSpy() {
  const navs = document.querySelectorAll("[data-toc]")
  if (navs.length === 0) return

  const offset = 96
  let raf = null

  function spyOne(nav) {
    const links = [...nav.querySelectorAll('a[href^="#"]')]
    let active = null
    for (const link of links) {
      const target = document.getElementById(decodeURIComponent(link.getAttribute("href").slice(1)))
      if (target && target.getBoundingClientRect().top <= offset) active = link
    }
    active = active || links[0]
    links.forEach((link) => link.classList.toggle("is-active", link === active))
  }

  function spy() {
    navs.forEach(spyOne)
  }

  window.addEventListener(
    "scroll",
    () => {
      if (raf) return
      raf = requestAnimationFrame(() => {
        raf = null
        spy()
      })
    },
    {passive: true}
  )

  spy()
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initTocScrollSpy)
} else {
  initTocScrollSpy()
}

const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")
const liveSocket = new LiveSocket("/live", Socket, {
  longPollFallbackMs: 2500,
  params: {_csrf_token: csrfToken},
  hooks: {...colocatedHooks, DragSort, SectionRail},
})

// Show progress bar on live navigation and form submits
topbar.config({barColors: {0: "#29d"}, shadowColor: "rgba(0, 0, 0, .3)"})
window.addEventListener("phx:page-loading-start", _info => topbar.show(300))
window.addEventListener("phx:page-loading-stop", _info => topbar.hide())

// connect if there are any LiveViews on the page
liveSocket.connect()

// expose liveSocket on window for web console debug logs and latency simulation:
// >> liveSocket.enableDebug()
// >> liveSocket.enableLatencySim(1000)  // enabled for duration of browser session
// >> liveSocket.disableLatencySim()
window.liveSocket = liveSocket

// The lines below enable quality of life phoenix_live_reload
// development features:
//
//     1. stream server logs to the browser console
//     2. click on elements to jump to their definitions in your code editor
//
if (process.env.NODE_ENV === "development") {
  window.addEventListener("phx:live_reload:attached", ({detail: reloader}) => {
    // Enable server log streaming to client.
    // Disable with reloader.disableServerLogs()
    reloader.enableServerLogs()

    // Open configured PLUG_EDITOR at file:line of the clicked element's HEEx component
    //
    //   * click with "c" key pressed to open at caller location
    //   * click with "d" key pressed to open at function component definition location
    let keyDown
    window.addEventListener("keydown", e => keyDown = e.key)
    window.addEventListener("keyup", _e => keyDown = null)
    window.addEventListener("click", e => {
      if(keyDown === "c"){
        e.preventDefault()
        e.stopImmediatePropagation()
        reloader.openEditorAtCaller(e.target)
      } else if(keyDown === "d"){
        e.preventDefault()
        e.stopImmediatePropagation()
        reloader.openEditorAtDef(e.target)
      }
    }, true)

    window.liveReloader = reloader
  })
}

