# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.CommentCard do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.comment_card/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  # Timestamps are relative to render time, so the header always reads
  # "5m ago" rather than drifting to an absolute date as the story ages.
  defp ago(seconds), do: DateTime.shift(DateTime.utc_now(), second: -seconds)

  # The card reads plain fields off the comment, so a map stands in for the
  # Ash struct.
  defp comment(overrides \\ %{}) do
    Map.merge(
      %{
        id: "comment-1",
        inserted_at: ago(300),
        body: "Confirmed against 3.12.13 — the crash reproduces.",
        author: %{display_name: "Sam Chen", avatar_url: nil},
        source: :varsel,
        github_author_login: nil,
        github_html_url: nil
      },
      overrides
    )
  end

  def variations do
    [
      %Variation{
        id: :default,
        description: "One comment: who wrote it, when, and the body.",
        attributes: %{row_id: "comment-default", comment: comment()}
      },
      %Variation{
        id: :markdown,
        description: "The body renders as markdown prose.",
        attributes: %{
          row_id: "comment-markdown",
          comment:
            comment(%{
              body: """
              The fix landed in **3.12.14**. Relevant commits:

              - `a1b2c3d` — bounds-check the frame header
              - `d4e5f6a` — regression test

              > Backporting to 3.11 is still open.
              """
            })
        }
      },
      %Variation{
        id: :deleted_author,
        description: "A comment outlives its author: a nil author reads as a deleted user.",
        attributes: %{
          row_id: "comment-deleted-author",
          comment: comment(%{author: nil, body: "Closing this out — duplicate of the OTP case."})
        }
      },
      %Variation{
        id: :from_github,
        description: """
        A comment read from the linked advisory: named by its GitHub login,
        with a link back to where it was written.
        """,
        attributes: %{
          row_id: "comment-from-github",
          comment:
            comment(%{
              author: nil,
              source: :github,
              github_author_login: "octocat",
              github_html_url:
                "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw#advisory-comment-1",
              body: "Maintainer here — we shipped the patch in 3.12.14."
            })
        }
      },
      %Variation{
        id: :from_github_claimed,
        description: """
        A GitHub comment whose login belongs to an account here: the person
        the case knows, with the login they signed it with.
        """,
        attributes: %{
          row_id: "comment-from-github-claimed",
          comment:
            comment(%{
              author: %{display_name: "Sam Chen", avatar_url: nil},
              source: :github,
              github_author_login: "samchen",
              github_html_url:
                "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw#advisory-comment-2",
              body: "Confirming from the advisory thread — the patch is in 3.12.14."
            })
        }
      },
      %Variation{
        id: :from_github_unknown_author,
        description: "A GitHub comment whose author GitHub did not name.",
        attributes: %{
          row_id: "comment-from-github-unknown",
          comment:
            comment(%{
              author: nil,
              source: :github,
              github_author_login: nil,
              github_html_url: nil,
              body: "Reported through the private form."
            })
        }
      },
      %Variation{
        id: :long_quiet,
        description: "An older comment falls back to an absolute date.",
        attributes: %{
          row_id: "comment-old",
          comment: comment(%{inserted_at: ago(2_600_000), body: "Reserved an ID for this."})
        }
      }
    ]
  end
end
