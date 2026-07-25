# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Layout.ThemeToggle do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.Layouts.theme_toggle/1

  def layout, do: :one_column

  def variations do
    [
      %Variation{
        id: :in_band,
        description: """
        System / light / dark. It lives in the navy nav band in both themes, so
        it uses fixed white-on-navy colours rather than theme-relative tokens —
        shown here on the band it belongs to.

        The sliding indicator follows the document's `data-theme`, which the
        storybook sets on the sandbox rather than on `<html>`, so it will not
        track the storybook's own theme switcher.
        """,
        template: """
        <div class="eef-band p-6 rounded-box flex justify-center">
          <.psb-variation/>
        </div>
        """
      },
      %Variation{
        id: :bare,
        description: "Out of the band, where the fixed white loses its contrast.",
        template: """
        <div class="p-2 flex justify-center">
          <.psb-variation/>
        </div>
        """
      }
    ]
  end
end
