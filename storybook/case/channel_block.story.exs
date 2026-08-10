# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.ChannelBlock do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AffectedComponents.channel_block/1

  def layout, do: :one_column

  def description, do: "One place a product ships, and the versions of it that carry the flaw."

  defp version(from, to, type \\ "semver", status \\ "affected") do
    %{"version" => from, "lessThan" => to, "status" => status, "versionType" => type}
  end

  def variations do
    [
      %Variation{
        id: :registry,
        description: "A registry channel: the ranges read as the published record will read them.",
        attributes: %{
          purl: "pkg:hex/ash_authentication_phoenix",
          versions: [version("1.0.0", "2.10.0")]
        },
        slots: [
          ~s(<:actions><span class="link link-hover text-primary">Edit</span></:actions>)
        ]
      },
      %Variation{
        id: :with_subpath,
        description: "A channel distributing one directory of a multi-application repository says which.",
        attributes: %{
          purl: "pkg:otp/ssh",
          subpath: "lib/ssh",
          versions: [
            version("0", "1.1.7", "otp", "unknown"),
            version("1.1.7", "5.2.11.10", "otp"),
            version("5.3", "5.5.2.3", "otp")
          ]
        },
        slots: [
          ~s(<:actions><span class="link link-hover text-primary">Edit</span><span class="link link-hover text-base-content/50">Remove</span></:actions>)
        ]
      },
      %Variation{
        id: :with_timeline,
        description:
          "The same ranges as a picture. Two affected spans with a safe gap between them " <>
            "is the shape a reader cannot get from the list alone.",
        attributes: %{
          purl: "pkg:otp/ssh",
          subpath: "lib/ssh",
          versions: [version("1.1.7", "5.2.11.10", "otp"), version("5.3", "5.5.2.3", "otp")],
          timeline_id: "story-channel-timeline",
          timeline: %{
            label: "ssh",
            nodes: [
              %{kind: :intro, tag: "1.1.7", pos: 6},
              %{kind: :fix, tag: "5.2.11.10", pos: 35},
              %{kind: :intro, tag: "5.3", pos: 65},
              %{kind: :fix, tag: "5.5.2.3", pos: 94}
            ],
            spans: [%{start: 6, stop: 35}, %{start: 65, stop: 94}]
          }
        }
      },
      %Variation{
        id: :repository,
        description:
          "The source repository is a channel like any other. It versions in commit SHAs, " <>
            "which have no order, so it carries ranges and no picture.",
        attributes: %{
          purl: "pkg:github/erlang/otp",
          versions: [
            version(
              "84adefa331c4159d432d22840663c38f155cd4c1",
              "c5210b42a9d3d96f3d25601942ce8122be0f3761",
              "git"
            )
          ]
        },
        slots: [
          ~s(<:actions><span class="link link-hover text-primary">Edit</span></:actions>)
        ]
      },
      %Variation{
        id: :service,
        description: "A service has no package to name, so it answers for its domain instead.",
        attributes: %{
          fallback: "hex.pm",
          versions: [version("2025-10-01", "2026-01-19", "date")]
        }
      },
      %Variation{
        id: :overridden,
        description: "A channel whose machinery was overridden by hand says so beside its name.",
        attributes: %{
          purl: "pkg:oci/gleam",
          versions: [version("v1.9.0", "v1.15.4", "other")]
        },
        slots: [
          ~s(<:badges><span class="badge badge-warning badge-xs">versions overridden</span></:badges>)
        ]
      },
      %Variation{
        id: :with_problem,
        description: "A problem belonging to one channel sits on that channel, not at the top of the card.",
        attributes: %{
          purl: "pkg:hex/plug",
          versions: [version("1.0.0", "*")]
        },
        slots: [
          ~s(<:problem><p class="mt-1 text-xs text-warning">⚠ fix c5210b4 has no containing release yet</p></:problem>)
        ]
      },
      %Variation{
        id: :nothing_derived,
        description: "Nothing walked yet: the block says so rather than showing an empty space.",
        attributes: %{purl: "pkg:hex/bandit", versions: []}
      },
      %Variation{
        id: :muted,
        description: "A row a pending suggestion would remove reads as already gone.",
        attributes: %{
          purl: "pkg:hex/plug",
          versions: [version("1.0.0", "2.0.0")],
          muted: true
        },
        slots: [
          ~s(<:badges><span class="badge badge-info badge-xs">removal proposed</span></:badges>)
        ]
      }
    ]
  end
end
