# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment.Source do
  @moduledoc """
  Where a comment was written.

  `label/1` gives the word the stream renders beside an author who is not a
  Varsel account.
  """

  use Ash.Type.Enum,
    values: [
      varsel: [
        label: "Varsel",
        description: "Written here, on the case's Comments tab."
      ],
      github: [
        label: "GitHub",
        description: "Written on the linked GitHub advisory and read from it."
      ]
    ]

  @doc "The word the stream renders for a comment's origin."
  @spec label(t()) :: String.t()
  def label(:varsel), do: "EEF CNA"
  def label(:github), do: "GitHub"
end
