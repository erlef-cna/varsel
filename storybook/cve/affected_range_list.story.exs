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

  # The rows `VarselWeb.CveHTML.affected_ranges/1` produces, spelled out here so
  # each shape can be seen without hunting for a record that happens to have it.
  defp ordered(fields) do
    Map.merge(
      %{
        kind: :ordered,
        lower: nil,
        lower_title: nil,
        fix: nil,
        fix_title: nil,
        branch_label: nil,
        fix_paren_label: nil,
        note: nil
      },
      fields
    )
  end

  defp git(fields) do
    Map.merge(%{kind: :git, intro_sha: nil, fix_shas: [], note: "git"}, fields)
  end

  def variations do
    [
      %Variation{
        id: :multi_line_semver,
        description:
          "The common shape (CVE-2026-90120's hex entry): one row per maintenance line. " <>
            "The first range spans lines, so it carries no branch label — its boundary " <>
            "still lines up with the labelled rows below it.",
        attributes: %{
          ranges: [
            ordered(%{
              lower: "0.1.0",
              fix: "1.16.6",
              note: "fixed in 1.16.6",
              fix_paren_label: "1.16 series"
            }),
            ordered(%{
              lower: "1.17.0",
              fix: "1.17.4",
              branch_label: "1.17 series",
              note: "fixed in 1.17.4"
            }),
            ordered(%{
              lower: "1.18.0",
              fix: "1.18.5",
              branch_label: "1.18 series",
              note: "fixed in 1.18.5"
            }),
            ordered(%{
              lower: "1.19.0",
              fix: "1.19.5",
              branch_label: "1.19 series",
              note: "fixed in 1.19.5"
            }),
            ordered(%{
              lower: "1.20.0",
              fix: "1.20.3",
              branch_label: "1.20 series",
              note: "fixed in 1.20.3"
            })
          ]
        }
      },
      %Variation{
        id: :single_range,
        description: "One line, no branch labels — the label column still reserves its space.",
        attributes: %{
          ranges: [ordered(%{lower: "0.5.9", fix: "0.5.11", note: "fixed in 0.5.11"})]
        }
      },
      %Variation{
        id: :unfixed,
        description: "An affected span with no fix yet: a lower bound alone, and the note says so.",
        attributes: %{
          ranges: [ordered(%{lower: "1.0.0", note: "no fix available"})]
        }
      },
      %Variation{
        id: :no_lower_bound,
        description:
          "A zero/absent lower bound never prints (R3) — everything below the fix is affected, " <>
            "so the row is upper-bound only.",
        attributes: %{
          ranges: [ordered(%{fix: "23.3.4.15", note: "fixed in 23.3.4.15"})]
        }
      },
      %Variation{
        id: :git_single_fix,
        description: "A git range with one fix commit.",
        attributes: %{
          ranges: [
            git(%{
              intro_sha: "f26876aa67aaeb38e616638aa3efbcc2fe2906a5",
              fix_shas: ["3f00dfad4e20ba88472e315c90a25742bf178f8e"]
            })
          ]
        }
      },
      %Variation{
        id: :git_many_fixes,
        description:
          "A fix plus its backports (CVE-2026-90120's github entry). Shas don't order, so " <>
            "there is no \"first\" fix to single out — every one of them prints.",
        attributes: %{
          ranges: [
            git(%{
              intro_sha: "f26876aa67aaeb38e616638aa3efbcc2fe2906a5",
              fix_shas: [
                "3f00dfad4e20ba88472e315c90a25742bf178f8e",
                "a6d1248659022749869963fd302687165ecf8c8b",
                "4167981747fe9ce75f374b94a28861ae950ea992",
                "149d9ed68fee0b4f77efd1e835ce5d785856697b",
                "eceb8315ce9a31ef784943a95a8624ebd1bc7e06"
              ]
            })
          ]
        }
      },
      %Variation{
        id: :git_unreleased,
        description: "A commit fix that no tagged release contains yet.",
        attributes: %{
          ranges: [
            git(%{
              intro_sha: "f26876aa67aaeb38e616638aa3efbcc2fe2906a5",
              note: "git — no tagged release contains the fix yet"
            })
          ]
        }
      },
      %Variation{
        id: :otp_release_with_unknown_era,
        description:
          "An OTP release channel whose vulnerability predates the repository's history: " <>
            "the pre-R13B03 era renders as its own row, and R-series versions sort below " <>
            "the modern numeric ones.",
        attributes: %{
          ranges: [
            ordered(%{lower: "0", fix: "R13B03", note: "unknown before R13B03"}),
            ordered(%{lower: "R13B03", fix: "27.3.4.15", note: "fixed in 27.3.4.15"}),
            ordered(%{
              lower: "28.0",
              fix: "28.5.0.4",
              branch_label: "28 series",
              note: "fixed in 28.5.0.4"
            }),
            ordered(%{
              lower: "29.0",
              fix: "29.0.4",
              branch_label: "29 series",
              note: "fixed in 29.0.4"
            })
          ]
        }
      },
      %Variation{
        id: :mixed_ordered_and_git,
        description:
          "Both row shapes in one block — the tones line up across them: lower bound and " <>
            "introducing commit warning, fix and fixing commits success.",
        attributes: %{
          ranges: [
            ordered(%{lower: "2.3.0", fix: "2.3.7", note: "fixed in 2.3.7"}),
            ordered(%{
              lower: "3.0.0-beta.1",
              fix: "3.0.0-beta.29",
              note: "fixed in 3.0.0-beta.29"
            }),
            git(%{
              intro_sha: "5bfbe1c5443bffe71cf1bf954bbdff61327d9a83",
              fix_shas: [
                "5204f88f9b2cdd9637a755337ed5f99185be5474",
                "69363432aa36760fc5438e4e17115d0f7c1b925a"
              ]
            })
          ]
        }
      },
      %Variation{
        id: :long_version_strings,
        description: "Long OTP-style versions and a long branch label, to check the column width holds.",
        attributes: %{
          ranges: [
            ordered(%{
              lower: "26.2.5.14",
              fix: "26.2.5.15",
              branch_label: "26.2 series",
              note: "fixed in 26.2.5.15"
            }),
            ordered(%{
              lower: "27.3.4.2",
              fix: "27.3.4.3",
              branch_label: "27.3 series",
              note: "fixed in 27.3.4.3"
            })
          ]
        }
      }
    ]
  end
end
