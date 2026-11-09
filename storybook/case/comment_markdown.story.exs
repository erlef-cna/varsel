# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CommentMarkdown do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.comment_markdown/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  @viewer "0190c0de-0000-7000-8000-00000000000a"
  @other "0190c0de-0000-7000-8000-00000000000b"

  def variations do
    [
      %Variation{
        id: :mentions,
        description: "A mention of someone else, and one of the viewer, filled.",
        attributes: %{
          viewer_id: @viewer,
          content: "[@Sam Chen](mention:#{@other}) and [@Ana Lima](mention:#{@viewer}), please review."
        }
      },
      %Variation{
        id: :shortcodes,
        description: "Emoji shortcodes render as emoji, in comments only.",
        attributes: %{content: "Shipped in 3.12.14 :rocket: thanks all :tada:"}
      },
      %Variation{
        id: :signed_out,
        description: "With no viewer, no mention is anyone's own.",
        attributes: %{content: "Ping [@Ana Lima](mention:#{@viewer})."}
      }
    ]
  end
end
