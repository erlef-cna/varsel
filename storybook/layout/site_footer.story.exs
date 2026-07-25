# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Layout.SiteFooter do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.Layouts.site_footer/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{
        id: :default,
        description: """
        The navy footer band: wordmark and blurb, then the Records / Process /
        More link columns and the licensing line. It takes no attributes — the
        link lists are compiled in.
        """
      }
    ]
  end
end
