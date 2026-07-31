# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Cve.CommitBoundaries do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CveView.commit_boundaries/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full font-mono text-sm"}

  @intro "f26876aa67aaeb38e616638aa3efbcc2fe2906a5"
  @fixes [
    "3f00dfad4e20ba88472e315c90a25742bf178f8e",
    "a6d1248659022749869963fd302687165ecf8c8b",
    "4167981747fe9ce75f374b94a28861ae950ea992"
  ]

  def variations do
    [
      %Variation{
        id: :single_fix,
        attributes: %{intro: @intro, fixes: Enum.take(@fixes, 1)}
      },
      %Variation{
        id: :many_fixes,
        description: "A fix and its backports. Commas stay muted so the shas carry the colour.",
        attributes: %{intro: @intro, fixes: @fixes}
      },
      %Variation{
        id: :intro_only,
        description: "Affected, no fix commit recorded yet.",
        attributes: %{intro: @intro}
      },
      %Variation{
        id: :fixes_only,
        description: "Fix commits with no recorded introduction — the leading label is dropped.",
        attributes: %{fixes: Enum.take(@fixes, 2)}
      }
    ]
  end
end
