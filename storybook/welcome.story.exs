# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Welcome do
  @moduledoc false
  use PhoenixStorybook.Story, :page

  def doc, do: "The component workbench for the EEF CNA console and public site."

  def render(assigns) do
    ~H"""
    <div class="prose prose-sm max-w-none">
      <p>
        Every rendering component in <code>lib/varsel_web/components</code>
        is listed here, grouped the same way the modules are:
      </p>

      <ul>
        <li>
          <strong>Core</strong>
          — <code>VarselWeb.CoreComponents</code>: the console shell (header band, panels,
          stat tiles), chips and states, tables, lists and pagination.
        </li>
        <li>
          <strong>Case workspace</strong>
          — <code>VarselWeb.CaseComponents</code>: the lifecycle stepper, section rail,
          activity feed, suggestion cards and diffs.
        </li>
        <li>
          <strong>Inputs</strong> — form fields, including the two LiveComponents
          (<code>CvssInput</code>, <code>MarkdownInput</code>).
        </li>
        <li>
          <strong>Layout</strong> — the site nav, footer, logo, flashes and theme toggle.
        </li>
      </ul>

      <p>
        Use the theme switcher in the header to check a component in both the light
        and dark daisyUI themes — components are rendered against the very same
        stylesheet the app uses (<code>assets/css/storybook.css</code>
        imports <code>app.css</code>), so what you see here is what the page renders.
      </p>

      <p>
        The storybook is <strong>development-only</strong>: it is mounted under the
        <code>:dev_routes</code>
        compile flag and its dependency is <code>only: [:dev, :test]</code>.
      </p>
    </div>
    """
  end
end
