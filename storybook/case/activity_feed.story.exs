# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ActivityFeed do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.activity_feed/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  # Timestamps are relative to render time, so the feed always reads "5m ago"
  # rather than drifting to an absolute date as the story ages.
  defp ago(seconds), do: DateTime.add(DateTime.utc_now(), -seconds, :second)

  def variations do
    [
      %Variation{
        id: :mixed,
        description: "Comments, suggestions and state changes interleaved, newest first.",
        attributes: %{
          entries: [
            %{
              kind: :comment,
              who: "Alex Rivera",
              at: ago(120),
              body: "Confirmed against 3.12.13 — the crash reproduces.",
              markdown?: true
            },
            %{
              kind: :proposal,
              who: "Sam Chen",
              at: ago(3_600),
              body: "suggested a change to ",
              chip: "case.description"
            },
            %{
              kind: :state,
              who: "Alex Rivera",
              at: ago(90_000),
              body: "moved this case to ",
              chip: "review"
            },
            %{
              kind: :system,
              who: "Varsel",
              at: ago(600_000),
              body: "reserved ",
              chip: "CVE-2026-1234"
            }
          ]
        }
      },
      %Variation{
        id: :markdown_comment,
        description: "`markdown?` renders the body as prose.",
        attributes: %{
          entries: [
            %{
              kind: :comment,
              who: "Sam Chen",
              at: ago(300),
              markdown?: true,
              body: """
              The fix landed in **3.12.14**. Relevant commits:

              - `a1b2c3d` — bounds-check the frame header
              - `d4e5f6a` — regression test
              """
            }
          ]
        }
      },
      %Variation{
        id: :with_suffix,
        description: "`chip` and `suffix` compose a sentence around a mono token.",
        attributes: %{
          entries: [
            %{
              kind: :state,
              who: "Alex Rivera",
              at: ago(45),
              body: "published ",
              chip: "CVE-2026-1234",
              suffix: " to MITRE."
            }
          ]
        }
      },
      %Variation{
        id: :empty,
        description: "An empty feed states so rather than rendering a bare rail.",
        attributes: %{entries: []}
      }
    ]
  end
end
