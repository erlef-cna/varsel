# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook do
  @moduledoc """
  Component workbench for local UI development, mounted at `/dev/storybook`.

  Lives under `dev/`, which `elixirc_paths/1` compiles only for `:dev` and
  `:test`, so neither this module nor the story scripts under `storybook/`
  reach a production build.

  Components render against `assets/css/storybook.css`, which imports
  `app.css` so a story looks exactly like the real page. Theme switching uses
  the `data_attribute` strategy: the sandbox gets `data-theme="light"` or
  `data-theme="dark"`, the same hook daisyUI's themes and the app's `--sev-*`
  / `--eef-*` custom properties key off.
  """
  use PhoenixStorybook,
    otp_app: :varsel,
    content_path: Path.expand("../storybook", __DIR__),
    # Remote (browser) paths, not file-system paths.
    css_path: "/assets/css/storybook.css",
    js_path: "/assets/js/storybook.js",
    sandbox_class: "varsel",
    themes: [light: [name: "Light"], dark: [name: "Dark"]],
    themes_strategies: [data_attribute: "theme"]
end
