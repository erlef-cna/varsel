// SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
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
import {AutoGrow, CssVars, DragSort, SectionRail} from "./hooks"

// Clipboard copies for `CoreComponents.copy_button/1`. The click already
// showed its own confirmation, so this only takes it back on failure.
window.addEventListener("varsel:clipcopy", (event) => {
  const button = event.target

  const failed = () => {
    clearTimeout(button.copyFailedTimer)
    button.classList.add("is-copy-failed")
    button.copyFailedTimer = setTimeout(() => button.classList.remove("is-copy-failed"), 1500)
  }

  // navigator.clipboard is absent outside a secure context.
  if (!navigator.clipboard) return failed()

  navigator.clipboard.writeText(event.detail.text).catch(failed)
})

// Copy button on a code block (`CoreComponents.code_copy_button/1`).
window.addEventListener("varsel:clipcode", (event) => copyCodeBlock(event.target))

function copyCodeBlock(button) {
  const code = button.closest(".codebox")?.querySelector("pre")
  if (!code) return

  // Lumis wraps each line in a block-level element *and* keeps the newline
  // that ends it, so `innerText` would count every break twice.
  button.dispatchEvent(
    new CustomEvent("varsel:clipcopy", {bubbles: true, detail: {text: code.textContent}})
  )
}

// The same button on controller-rendered pages, where no LiveView is running
// to interpret its `phx-click`. Those carry `data-clipcode` instead, and the
// confirmation `JS.transition` would have applied is done by hand.
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-clipcode]")
  if (!button) return

  clearTimeout(button.copiedTimer)
  button.classList.add("is-copied")
  button.copiedTimer = setTimeout(() => button.classList.remove("is-copied"), 1500)

  copyCodeBlock(button)
})

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
  hooks: {...colocatedHooks, AutoGrow, DragSort, SectionRail, CssVars},
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

