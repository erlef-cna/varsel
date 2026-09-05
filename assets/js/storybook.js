// SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
//
// SPDX-License-Identifier: Apache-2.0

// Loaded immediately before PhoenixStorybook's own JS. Declares the app's
// LiveView hooks on `window.storybook` so hook-driven components (the section
// rail, the timeline's CSS custom properties, drag-sortable lists) behave in a
// story exactly as they do on the real page.

import "phoenix_html"
import {hooks as colocatedHooks} from "phoenix-colocated/varsel"
import * as Hooks from "./hooks"
import {install as installPriorityNav} from "./priority_nav"

installPriorityNav()

;(function () {
  window.storybook = {Hooks: {...colocatedHooks, ...Hooks}}
})()
