# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.AdvisoryCard do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AdvisoryComponents.advisory_card/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  defp link(overrides) do
    Map.merge(
      %{
        ghsa_id: "GHSA-pwvh-c689-f8q5",
        owner: "erlang",
        repo: "otp",
        html_url: "https://github.com/erlang/otp/security/advisories/GHSA-pwvh-c689-f8q5",
        state: :published,
        title: "Unbounded resource use in inets",
        cve_id: "CVE-2026-48858",
        fetched_at: ~U[2026-09-05 12:00:00Z]
      },
      overrides
    )
  end

  def variations do
    [
      %Variation{
        id: :published,
        description: "A published advisory the viewer may refresh and unlink.",
        attributes: %{link: link(%{}), can_refresh: true, can_unlink: true}
      },
      %Variation{
        id: :draft,
        description: "A draft, still private on GitHub, with no CVE ID yet.",
        attributes: %{
          link:
            link(%{
              state: :draft,
              cve_id: nil,
              title: "Header injection in acme_lib",
              owner: "acme",
              repo: "acme_lib"
            }),
          can_refresh: true
        }
      },
      %Variation{
        id: :busy,
        description: "While a request to GitHub runs, the actions are held.",
        attributes: %{link: link(%{}), can_refresh: true, can_unlink: true, busy: true}
      },
      %Variation{
        id: :read_only,
        description: "A viewer who may neither refresh nor unlink sees the facts alone.",
        attributes: %{link: link(%{state: :withdrawn})}
      }
    ]
  end
end
