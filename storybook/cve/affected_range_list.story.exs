# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Cve.AffectedRangeList do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CveView.affected_range_list/1

  def layout, do: :one_column

  # Range lines are block-level rows that lay out against the Affected card's
  # full width in the app, not centered in the sandbox.
  def container, do: {:div, class: "w-full"}

  # Every shape `versions[]` can take, spelled out as the rows
  # `VarselWeb.CveHTML.affected_ranges/1` produces — several of these need a
  # specific record to exist before they can be seen on a real page.
  defp row(fields) do
    Map.merge(
      %{
        kind: :ordered,
        lower: nil,
        lower_title: nil,
        upper: nil,
        upper_title: nil,
        upper_inclusive?: false,
        open?: false,
        single?: false,
        status: :affected,
        after_status: :unaffected,
        changes: [],
        branch_label: nil
      },
      fields
    )
  end

  defp change(at, status), do: %{at: at, at_title: at, status: status}

  def variations do
    [
      %Variation{
        id: :multi_line_semver,
        description:
          "The common shape (CVE-2026-90120's hex entry): one bounded range per maintenance " <>
            "line, every one affected. The first spans every line from 0.1 to 1.16, so it " <>
            "belongs to no single series and carries no label.",
        attributes: %{
          default_status: "unaffected",
          ranges: [
            row(%{lower: "0.1.0", upper: "1.16.6"}),
            row(%{lower: "1.17.0", upper: "1.17.4", branch_label: "1.17 series"}),
            row(%{lower: "1.18.0", upper: "1.18.5", branch_label: "1.18 series"}),
            row(%{lower: "1.19.0", upper: "1.19.5", branch_label: "1.19 series"}),
            row(%{lower: "1.20.0", upper: "1.20.3", branch_label: "1.20 series"})
          ]
        }
      },
      %Variation{
        id: :every_status,
        description:
          "Each status in turn. An `unaffected` or `unknown` entry is as real as an affected " <>
            "one — colour carries the difference, and nothing is inferred.",
        attributes: %{
          default_status: "unaffected",
          ranges: [
            row(%{lower: "1.0.0", upper: "2.0.0", status: :affected}),
            row(%{lower: "2.0.0", upper: "2.5.0", status: :unaffected}),
            row(%{lower: "2.5.0", upper: "3.0.0", status: :unknown})
          ]
        }
      },
      %Variation{
        id: :changes_chain,
        description:
          "An open range refined by `changes[]`. Transitions print in the record's own array " <>
            "order — the order the resolution algorithm applies them — each in the colour of " <>
            "the status it switches to, including a switch BACK to affected.",
        attributes: %{
          default_status: "unaffected",
          ranges: [
            row(%{
              lower: "0.6.0",
              open?: true,
              status: :affected,
              changes: [
                change("1.7.22", :unaffected),
                change("1.8.0", :affected),
                change("1.8.6", :unaffected)
              ]
            })
          ]
        }
      },
      %Variation{
        id: :bounds,
        description:
          "`lessThan` is exclusive and prints `<`; `lessThanOrEqual` includes its own value " <>
            "and prints `≤`; `lessThan: \"*\"` has no upper bound at all.",
        attributes: %{
          default_status: "unaffected",
          ranges: [
            row(%{lower: "1.0.0", upper: "2.0.0"}),
            row(%{lower: "3.0.0", upper: "3.9.9", upper_inclusive?: true}),
            row(%{lower: "4.0.0", open?: true})
          ]
        }
      },
      %Variation{
        id: :single_version,
        description: "An entry naming ONE version takes no operator at all.",
        attributes: %{
          default_status: "unaffected",
          ranges: [row(%{lower: "1.2.3", single?: true})]
        }
      },
      %Variation{
        id: :zero_lower_bound,
        description:
          "The `0` sentinel means \"from the start\", so it prints as an upper-bound-only line " <>
            "rather than a literal version.",
        attributes: %{
          default_status: "unaffected",
          ranges: [row(%{upper: "23.3.4.15"})]
        }
      },
      %Variation{
        id: :otp_with_unknown_era,
        description:
          "CVE-2026-900001's release channel: everything below the first affected release is " <>
            "explicitly unknown — the repository's history does not reach back that far — " <>
            "then affected up two lines.",
        attributes: %{
          default_status: "unaffected",
          ranges: [
            row(%{upper: "17.0", status: :unknown}),
            row(%{lower: "17.0", upper: "27.3.4.15"}),
            row(%{lower: "28.0", upper: "28.5.0.4", branch_label: "maint-28"}),
            row(%{lower: "29.0", upper: "29.0.4", branch_label: "maint-29"})
          ]
        }
      },
      %Variation{
        id: :default_affected,
        description:
          "An inverted record: everything is affected EXCEPT the listed range. The closing " <>
            "line carries that, and without it the block would read backwards.",
        attributes: %{
          default_status: "affected",
          ranges: [row(%{lower: "4.2.0", open?: true, status: :unaffected})]
        }
      },
      %Variation{
        id: :default_unknown,
        description:
          "44 entries in the corpus default to `unknown`: the record speaks only about the " <>
            "ranges it lists and says nothing about anything else.",
        attributes: %{
          default_status: "unknown",
          ranges: [row(%{lower: "1.0.0", upper: "1.4.0"})]
        }
      },
      %Variation{
        id: :git_commits,
        description:
          "A commit-versioned entry. Shas shorten to 7 characters, each keeping its full value " <>
            "in a title, and read in the same grammar as a version range.",
        attributes: %{
          default_status: "unaffected",
          ranges: [
            row(%{
              kind: :git,
              lower: "f26876aa67aaeb38e616638aa3efbcc2fe2906a5",
              upper: "3f00dfad4e20ba88472e315c90a25742bf178f8e",
              # Shas cannot be resolved, so the bound takes no colour.
              after_status: nil
            })
          ]
        }
      },
      %Variation{
        id: :dates,
        description: "A hosted service versions itself by date; the same grammar applies.",
        attributes: %{
          default_status: "unaffected",
          ranges: [row(%{upper: "2026-03-10"})]
        }
      }
    ]
  end
end
