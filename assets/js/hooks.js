// SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
//
// SPDX-License-Identifier: Apache-2.0

// The app's LiveView hooks, shared by the main bundle (assets/js/app.js) and
// the storybook bundle (assets/js/storybook.js) so a story behaves like the
// real page.

import Sortable from "sortablejs"

// Drag & drop list reordering: sorts the container's [data-drag-id] children
// via Sortable.js and pushes the container's data-sort-event with the ids in
// their new order once a drag finishes.
export const DragSort = {
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

// Drag & drop of a board's cards between the columns of their own row. A
// [data-card] is dragged; the [data-column] cells of its [data-row] are the
// drop targets. On drag start the board asks the server (data-targets-event)
// which columns the card may move to and marks each other cell of the row
// data-drop="allowed" or "denied", which is what reveals the cell's
// placeholder, sized to the dragged card through --board-card-height. Dropping on an allowed cell pushes data-move-event with the
// card and the column.
export const BoardMove = {
  mounted() {
    this.drag = null

    this.clear = () => {
      for (const cell of this.el.querySelectorAll("[data-drop], [data-drop-over]")) {
        cell.removeAttribute("data-drop")
        cell.removeAttribute("data-drop-over")
      }
      this.drag = null
      this.over = null
    }

    this.targetCell = (event) => {
      const cell = event.target.closest?.("[data-column]")
      return this.drag && cell && cell.closest("[data-row]") === this.drag.row ? cell : null
    }

    this.el.addEventListener("dragstart", (event) => {
      const card = event.target.closest?.("[data-card]")
      if (!card) return

      const id = card.dataset.card
      const row = card.closest("[data-row]")
      const from = card.closest("[data-column]")
      this.drag = {id, row}
      this.el.style.setProperty("--board-card-height", `${card.offsetHeight}px`)
      event.dataTransfer.effectAllowed = "move"
      event.dataTransfer.setData("text/plain", id)

      this.pushEvent(this.el.dataset.targetsEvent, {id}, ({targets}) => {
        if (this.drag?.id !== id) return

        for (const cell of row.querySelectorAll("[data-column]")) {
          if (cell !== from) {
            cell.dataset.drop = targets.includes(cell.dataset.column) ? "allowed" : "denied"
          }
        }
      })
    })

    this.el.addEventListener("dragover", (event) => {
      const cell = this.targetCell(event)

      if (this.over && this.over !== cell) this.over.removeAttribute("data-drop-over")

      if (!this.drag) return

      // LiveView accepts every dragover page-wide for its upload drop
      // targets, so a refused cell has to say so itself to get the
      // not-allowed cursor.
      if (cell?.dataset.drop === "allowed") {
        event.preventDefault()
        event.dataTransfer.dropEffect = "move"
        cell.dataset.dropOver = ""
        this.over = cell
      } else {
        event.dataTransfer.dropEffect = "none"
      }
    })

    this.el.addEventListener("drop", (event) => {
      const cell = this.targetCell(event)

      if (cell?.dataset.drop === "allowed") {
        event.preventDefault()
        this.pushEvent(this.el.dataset.moveEvent, {id: this.drag.id, to: cell.dataset.column})
      }

      this.clear()
    })

    this.el.addEventListener("dragend", this.clear)
  },
}

// Remembers the cases board's view (its two sorts and its assignee filter)
// across visits. The element carries what the URL names (data-sort,
// data-packages, data-assignee; absent for a default). A visit whose URL
// names none of them gets the remembered ones back through the restore_view
// event. A force-refresh, which the root layout marks on the body, forgets
// them and resets the board; the mark lasts as long as the page, so it is
// honoured once.
const BOARD_MEMORY_KEY = "cases:view"
let forceReloadHonoured = false

const namesAny = (view) => Boolean(view?.sort || view?.packages || view?.assignee)

export const BoardMemory = {
  chosen() {
    const {sort = null, packages = null, assignee = null} = this.el.dataset
    return {sort, packages, assignee}
  },
  remember() {
    const chosen = this.chosen()

    if (namesAny(chosen)) {
      localStorage.setItem(BOARD_MEMORY_KEY, JSON.stringify(chosen))
    } else {
      localStorage.removeItem(BOARD_MEMORY_KEY)
    }
  },
  remembered() {
    try {
      return JSON.parse(localStorage.getItem(BOARD_MEMORY_KEY))
    } catch (_error) {
      return null
    }
  },
  mounted() {
    const named = namesAny(this.chosen())

    if (document.body.hasAttribute("data-force-reload") && !forceReloadHonoured) {
      forceReloadHonoured = true
      localStorage.removeItem(BOARD_MEMORY_KEY)
      if (named) this.pushEvent("restore_view", {})
    } else if (named) {
      this.remember()
    } else if (namesAny(this.remembered())) {
      this.pushEvent("restore_view", this.remembered())
    }
  },
  updated() {
    this.remember()
  },
}

// Narrows a console menu's options to the ones whose label contains what is
// typed in its search box. LiveView patches drop the `hidden` marks, so they
// are re-applied after each one. The arrow keys walk from the trigger to the
// search box and on through the options that are left, and back up.
export const MenuFilter = {
  mounted() {
    this.input = this.el.querySelector("[data-menu-filter]")
    this.input.addEventListener("input", () => this.apply())
    this.input.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return
      event.preventDefault()
      this.stops()[1]?.click()
    })
    this.el.querySelector("[role=button]").addEventListener("click", () => this.input.focus())
    this.el.addEventListener("keydown", (event) => this.walk(event))
  },
  stops() {
    return [this.input, ...this.el.querySelectorAll("[data-menu-option]:not([hidden]) button")]
  },
  walk(event) {
    const stops = this.stops()
    const at = stops.indexOf(document.activeElement)
    const last = stops.length - 1

    const to = {
      ArrowDown: Math.min(at + 1, last),
      ArrowUp: Math.max(at - 1, 0),
      Home: at > 0 ? 1 : null,
      End: at > 0 ? last : null,
    }[event.key]

    if (event.key === "Escape") {
      document.activeElement.blur()
    } else if (stops[to]) {
      event.preventDefault()
      stops[to].focus()
      stops[to].scrollIntoView({block: "nearest"})
    }
  },
  updated() {
    this.apply()
  },
  apply() {
    const term = this.input.value.trim().toLowerCase()
    let shown = 0

    for (const option of this.el.querySelectorAll("[data-menu-option]")) {
      option.hidden = !option.dataset.menuOption.toLowerCase().includes(term)
      if (!option.hidden) shown += 1
    }

    this.el.querySelector("[data-menu-empty]").hidden = shown > 0
  },
}

// Applies dynamic, per-render style values without an inline `style`
// attribute, which the strict Content-Security-Policy forbids. Every
// `data-css-*` attribute is written to the element's CSSOM style
// (`el.style.setProperty`), which CSP does not govern. Property name is the
// suffix verbatim, so `data-css---tl-pos` sets the `--tl-pos` custom property
// (the `--` of a custom property is preserved after the `data-css-` prefix) and
// `data-css-background` sets `background`. Re-applied on every LiveView
// patch so streamed diffs keep their values.
export const CssVars = {
  apply() {
    for (const {name, value} of this.el.attributes) {
      if (name.startsWith("data-css-")) {
        this.el.style.setProperty(name.slice("data-css-".length), value)
      }
    }
  },
  mounted() {
    this.apply()
  },
  updated() {
    this.apply()
  },
}

// Grows a textarea to fit its content while it is being edited, so a long
// description is written without scrolling inside a fixed-height box. The
// `rows` attribute is the resting height: the field expands on focus (and
// keeps up with typing), then collapses back on blur so a form of several
// fields stays scannable.
//
// Height is set through the CSSOM (`el.style.height`) rather than an inline
// `style` attribute, which the strict Content-Security-Policy forbids — see
// `CssVars`. Growing needs the element collapsed first, since `scrollHeight`
// never reports less than the current height.
//
// That collapse shortens the document, and a page scrolled past the new
// maximum is clamped to it — the position is not restored when the height
// comes back, so on a form taller than the viewport every keystroke walks the
// page upward. Flooring the wrapper at its current height keeps the document
// the same length across the measurement, leaving nothing to clamp.
//
// Growth stops at the field's CSS `max-height`, past which the textarea
// scrolls its own content: a field taller than the window can never bring the
// caret and the surrounding form on screen together, so growing further only
// moves the page under the writer.
export const AutoGrow = {
  grow() {
    const frame = this.el.closest("[data-autogrow-frame]")
    if (frame) frame.style.minHeight = `${frame.offsetHeight}px`

    this.el.style.height = "auto"
    const cap = parseFloat(getComputedStyle(this.el).maxHeight)
    const fit = this.el.scrollHeight
    this.el.style.height = `${Number.isFinite(cap) ? Math.min(fit, cap) : fit}px`

    if (frame) frame.style.minHeight = ""
  },
  collapse() {
    this.el.style.height = ""
  },
  mounted() {
    // A textarea that sizes itself must not also be hand-resizable: the two
    // fight, and the next keystroke would discard the dragged height.
    this.el.style.resize = "none"
    this.listeners = {
      input: () => this.grow(),
      focus: () => this.grow(),
      blur: () => this.collapse(),
    }

    for (const [event, listener] of Object.entries(this.listeners)) {
      this.el.addEventListener(event, listener)
    }
  },
  updated() {
    // A LiveView patch re-renders the textarea mid-edit; only the focused one
    // should be tall, and the rest keep their resting height.
    if (document.activeElement === this.el) this.grow()
  },
  destroyed() {
    for (const [event, listener] of Object.entries(this.listeners)) {
      this.el.removeEventListener(event, listener)
    }
  },
}

// Where character `index` of `textarea` sits, relative to the textarea's
// border box: a hidden copy of the field, styled alike, holds the text up to
// `index` followed by a marker span whose offset is the answer.
function caretPosition(textarea, index) {
  const style = getComputedStyle(textarea)
  const mirror = document.createElement("div")
  const scrollbar = textarea.offsetWidth - textarea.clientWidth -
    parseFloat(style.borderLeftWidth) - parseFloat(style.borderRightWidth)

  for (const property of [
    "boxSizing", "borderTopWidth", "borderRightWidth", "borderBottomWidth", "borderLeftWidth",
    "borderStyle", "paddingTop", "paddingRight", "paddingBottom", "paddingLeft",
    "fontFamily", "fontSize", "fontWeight", "fontStyle", "fontVariant", "lineHeight",
    "letterSpacing", "wordSpacing", "textTransform", "textIndent", "tabSize",
  ]) {
    mirror.style[property] = style[property]
  }

  Object.assign(mirror.style, {
    position: "absolute",
    visibility: "hidden",
    top: "0",
    left: "0",
    overflow: "hidden",
    whiteSpace: "pre-wrap",
    overflowWrap: "break-word",
    width: `${textarea.offsetWidth - scrollbar}px`,
  })

  const marker = document.createElement("span")
  marker.textContent = textarea.value.slice(index) || "."
  mirror.textContent = textarea.value.slice(0, index)
  mirror.appendChild(marker)
  document.body.appendChild(mirror)

  const position = {
    top: marker.offsetTop - textarea.scrollTop,
    left: marker.offsetLeft - textarea.scrollLeft,
    height: parseFloat(style.lineHeight) || marker.offsetHeight,
  }

  mirror.remove()
  return position
}

// The comment composer's `@`-mention menu, beside its textarea.
//
// Typing `@` offers the people in `data-candidates` ([{id, name}]); picking
// one writes the mention markdown the server reads back,
// `[@Name](mention:<id>)` and dispatches `input`, so the form's phx-change
// and AutoGrow see the new value. When nobody matches, the menu says so.
//
// The textarea is found through the composer root on every event: a LiveView
// patch may swap it, and the hook element itself is `phx-update="ignore"`.
export const CommentAssist = {
  mounted() {
    this.root = this.el.closest("[data-comment-composer]")
    this.menu = this.el.querySelector("[data-mention-menu]")
    this.matches = []
    this.active = 0
    this.trigger = null

    this.listeners = {
      input: (e) => e.target.tagName === "TEXTAREA" && this.update(),
      keydown: (e) => e.target.tagName === "TEXTAREA" && this.keydown(e),
      focusout: (e) => e.target.tagName === "TEXTAREA" && this.close(),
    }

    for (const [event, listener] of Object.entries(this.listeners)) {
      this.root.addEventListener(event, listener)
    }
  },
  destroyed() {
    for (const [event, listener] of Object.entries(this.listeners)) {
      this.root.removeEventListener(event, listener)
    }
  },
  textarea() {
    return this.root.querySelector("textarea")
  },
  candidates() {
    try {
      return JSON.parse(this.el.dataset.candidates || "[]")
    } catch (_error) {
      return []
    }
  },
  update() {
    const textarea = this.textarea()
    const before = textarea.value.slice(0, textarea.selectionStart)
    const match = before.match(/(?:^|[\s(])@([^\s@[\]()]{0,40})$/)

    if (!match) return this.close()

    const query = match[1].toLowerCase()
    this.trigger = textarea.selectionStart - match[1].length - 1
    this.matches = this.candidates()
      .filter((person) => person.name.toLowerCase().includes(query))
      .slice(0, 8)
    this.active = 0

    if (this.matches.length) return this.render()

    this.notice("No one in the case matches.")
  },
  notice(text) {
    const item = document.createElement("li")
    item.className = "px-2 py-1 text-base-content/50"
    item.textContent = text
    this.menu.replaceChildren(item)
    this.open()
  },
  keydown(e) {
    if (e.key === "Escape" && !this.menu.classList.contains("hidden")) {
      e.preventDefault()
      return this.close()
    }

    if (!this.matches.length) return

    const moves = {ArrowDown: 1, ArrowUp: -1}

    if (e.key in moves) {
      e.preventDefault()
      this.active = (this.active + moves[e.key] + this.matches.length) % this.matches.length
      this.render()
    } else if (e.key === "Enter" || e.key === "Tab") {
      e.preventDefault()
      this.pick(this.active)
    }
  },
  render() {
    this.menu.replaceChildren(
      ...this.matches.map((person, index) => {
        const option = document.createElement("li")
        option.id = `${this.el.id}-option-${index}`
        option.setAttribute("role", "option")
        option.setAttribute("aria-selected", String(index === this.active))
        option.className = `cursor-pointer rounded px-2 py-1 ${index === this.active ? "bg-base-200 font-semibold" : ""}`
        option.textContent = person.name
        // mousedown, so the textarea keeps its focus and caret.
        option.addEventListener("mousedown", (e) => {
          e.preventDefault()
          this.pick(index)
        })
        return option
      }),
    )
    this.open()
  },
  // Shows the menu just under the line holding the `@`. It is positioned
  // against the textarea's frame, so validation errors appearing or clearing
  // below the field leave it in place. The offsetParent only exists once the
  // menu is displayed.
  open() {
    this.menu.classList.remove("hidden")

    const textarea = this.textarea()
    const parent = this.menu.offsetParent
    if (!parent || this.trigger === null) return

    const field = textarea.getBoundingClientRect()
    const frame = parent.getBoundingClientRect()
    const caret = caretPosition(textarea, this.trigger)
    const maxLeft = field.right - frame.left - this.menu.offsetWidth

    this.menu.style.top = `${field.top - frame.top + caret.top + caret.height + 4}px`
    this.menu.style.left = `${Math.max(0, Math.min(field.left - frame.left + caret.left, maxLeft))}px`
  },
  close() {
    this.matches = []
    this.trigger = null
    this.menu.classList.add("hidden")
    this.menu.replaceChildren()
  },
  pick(index) {
    const person = this.matches[index]
    const textarea = this.textarea()
    if (!person || this.trigger === null) return this.close()

    const name = person.name.replace(/[[\]]/g, "")
    this.replace(textarea, this.trigger, textarea.selectionStart, `[@${name}](mention:${person.id}) `)
    this.close()
  },
  replace(textarea, from, to, text) {
    textarea.focus()
    textarea.setRangeText(text, from, to, "end")
    textarea.dispatchEvent(new Event("input", {bubbles: true}))
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
export const SectionRail = {
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
