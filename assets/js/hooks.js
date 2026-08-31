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
