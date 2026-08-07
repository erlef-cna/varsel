# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Cve.Reference do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CveView.reference/1

  def layout, do: :one_column

  # The component is a link followed by inline pills, so without a column the
  # variations of a group would run together on one line.
  def container, do: {:div, class: "flex w-full flex-col items-start gap-1"}

  def variations do
    [
      %VariationGroup{
        id: :identifiers,
        description:
          "A URL whose shape carries an identifier reads as that identifier: it is what someone " <>
            "recognises, where the path to it is noise. The full URL stays in the href and the title.",
        variations: [
          %Variation{
            id: :commit,
            attributes: %{
              url: "https://github.com/erlang/otp/commit/0123456789abcdef0123456789abcdef01234567",
              tags: ["patch"]
            }
          },
          %Variation{
            id: :ghsa,
            attributes: %{
              url: "https://github.com/gleam-lang/gleam/security/advisories/GHSA-4vvc-458m-r82g",
              tags: ["vendor-advisory"]
            }
          },
          %Variation{
            id: :osv,
            attributes: %{
              url: "https://osv.dev/vulnerability/EEF-CVE-2026-9012",
              tags: ["related"]
            }
          }
        ]
      },
      %VariationGroup{
        id: :plain_links,
        description:
          "Everything else reads as its own URL — including GitHub paths that only look like the " <>
            "shapes above. A `name` overrides that where the URL says less than a title would.",
        variations: [
          %Variation{
            id: :bare,
            attributes: %{
              url: "https://example.com/advisories/2026-001",
              tags: ["third-party-advisory"]
            }
          },
          %Variation{
            id: :github_but_neither,
            attributes: %{
              url: "https://github.com/erlef/varsel/issues/1",
              tags: ["issue-tracking"]
            }
          },
          %Variation{
            id: :named,
            attributes: %{
              url: "https://example.com/blog/2026/03/deep-dive",
              name: "Upstream write-up",
              tags: ["technical-description"]
            }
          }
        ]
      },
      %VariationGroup{
        id: :tags,
        description:
          "Advisory tags are warn-toned, every other tag muted; an untagged reference gets no " <>
            "pill at all, since absence is honest. `pills` decides how many are drawn — the " <>
            "published card shows the first, an editor shows everything the row carries.",
        variations: [
          %Variation{
            id: :untagged,
            attributes: %{url: "https://example.com/notes"}
          },
          %Variation{
            id: :first_pill_only,
            attributes: %{
              url: "https://cna.erlef.org/cves/CVE-2026-90116.html",
              tags: ["related", "third-party-advisory"]
            }
          },
          %Variation{
            id: :every_pill,
            attributes: %{
              url: "https://cna.erlef.org/cves/CVE-2026-90116.html",
              tags: ["related", "third-party-advisory"],
              pills: :all
            }
          }
        ]
      },
      %Variation{
        id: :broken_link,
        description:
          "A `broken-link` reference renders faint but stays listed and clickable — struck " <>
            "through would read as retracted, and the URL is still the best record of what was cited.",
        attributes: %{
          url: "https://gone.example.com/advisory",
          tags: ["broken-link"]
        }
      }
    ]
  end
end
