# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CommentReaction.Emoji do
  @moduledoc """
  The emoji a comment can be reacted with. `label/1` is the emoji itself and
  `description/1` its name.
  """

  use Ash.Type.Enum,
    values: [
      thumbs_up: [label: "👍", description: "thumbs up"],
      thumbs_down: [label: "👎", description: "thumbs down"],
      laugh: [label: "😄", description: "laugh"],
      hooray: [label: "🎉", description: "hooray"],
      confused: [label: "😕", description: "confused"],
      heart: [label: "❤️", description: "heart"],
      rocket: [label: "🚀", description: "rocket"],
      eyes: [label: "👀", description: "eyes"]
    ]
end
