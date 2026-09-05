// SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
//
// SPDX-License-Identifier: Apache-2.0

// Priority+ navigation for `VarselWeb.Layouts.site_nav/1`: the header shows
// as many menu items as fit and pushes the rest into the "More" dropdown.
// The visible count is a set of classes on the gauge element, which app.css
// turns into per-index rules. The gauge is `phx-update="ignore"`, so the
// classes survive LiveView patches.

const GAUGE = ".priority-nav-gauge"

function measure(gauge) {
  const nav = gauge.parentElement
  const list = nav.querySelector(".priority-nav")
  if (!list) return
  const items = [...list.children]

  gauge.className = "priority-nav-gauge nav-overflow"
  const withMore = list.getBoundingClientRect().width
  gauge.classList.remove("nav-overflow")
  const withoutMore = list.getBoundingClientRect().width

  const gap = parseFloat(getComputedStyle(list).columnGap) || 0
  const widths = items.map((item) => item.getBoundingClientRect().width)
  const total = widths.reduce((sum, width, i) => sum + width + (i > 0 ? gap : 0), 0)

  let fit = items.length
  if (total > withoutMore + 0.5) {
    fit = 0
    let used = 0
    for (const width of widths) {
      const next = used + (fit > 0 ? gap : 0) + width
      if (next > withMore + 0.5) break
      used = next
      fit++
    }
  }

  gauge.className = ["priority-nav-gauge", "nav-ready", `nav-visible-${fit}`, fit < items.length && "nav-overflow"]
    .filter(Boolean)
    .join(" ")
}

const attached = new WeakSet()

function scan() {
  for (const gauge of document.querySelectorAll(GAUGE)) {
    if (!attached.has(gauge)) {
      attached.add(gauge)
      new ResizeObserver(() => measure(gauge)).observe(gauge.parentElement)
    }
    measure(gauge)
  }
}

// The active nav item is bolder, so a LiveView patch changes item widths.
export function install() {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scan)
  } else {
    scan()
  }
  window.addEventListener("phx:page-loading-stop", scan)
  document.fonts?.ready.then(scan)
}
