# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.AdvisoryDiff do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AdvisoryComponents.advisory_diff/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"

  def variations do
    [
      %Variation{
        id: :mixed,
        description: "Every status at once: a case partly in step with its advisory.",
        attributes: %{
          rows: [
            %{
              field: :title,
              ours: "Unbounded resource use in inets",
              theirs: "Unbounded resource use in inets",
              status: :same
            },
            %{
              field: :description,
              ours: "### Summary\n\nThe inets HTTP server allocates without limit.\n\n### Solutions\n\nUpgrade.",
              theirs: "The inets HTTP server allocates without limit.",
              status: :differs
            },
            %{field: :cve_id, ours: "CVE-2026-48858", theirs: nil, status: :ours_only},
            %{field: :cvss_v4, ours: nil, theirs: @vector, status: :theirs_only},
            %{field: :weaknesses, ours: [770, 400], theirs: [770], status: :differs},
            %{
              field: :credits,
              ours: [
                %{login: "garazdawi", name: "Lukas Larsson", roles: [:reporter, :finder]},
                %{login: nil, name: "Someone Offline", roles: [:analyst]}
              ],
              theirs: [
                %{login: "garazdawi", name: "garazdawi", roles: [:reporter]},
                %{login: "whaileee", name: "whaileee", roles: [:remediation_reviewer]}
              ],
              status: :differs
            },
            %{
              field: :affected,
              package: "OTP",
              ours: %{ranges: [">= 17.0"], patched: ["27.3.4.17", "28.5.0.6", "29.0.6"]},
              theirs: %{ranges: [">= 17.0"], patched: ["29.0.6", "28.5.0.6", "27.3.4.17"]},
              status: :same
            },
            %{
              field: :affected,
              package: "otp/inets",
              ours: %{ranges: [], patched: []},
              theirs: %{ranges: [">= 5.10"], patched: ["9.7.2", "9.6.2.3", "9.3.2.7"]},
              status: :not_derived
            },
            %{
              field: :affected,
              package: "hex/acme_extra",
              ours: %{ranges: ["< 0.3.0"], patched: ["0.3.0"]},
              theirs: nil,
              status: :ours_only
            }
          ]
        }
      },
      %Variation{
        id: :pullable,
        description: "A viewer who may edit the case is offered a pull per row the advisory can add to.",
        attributes: %{
          can_pull: true,
          rows: [
            %{
              field: :title,
              ours: "Header injection",
              theirs: "Header injection in acme_lib",
              status: :differs
            },
            %{field: :cvss_v4, ours: nil, theirs: @vector, status: :theirs_only},
            %{field: :weaknesses, ours: [113], theirs: [113], status: :same},
            %{
              field: :credits,
              ours: [],
              theirs: [%{login: "alice", name: "alice", roles: [:finder]}],
              status: :theirs_only
            },
            %{
              field: :affected,
              package: "erlang/acme_lib",
              ours: nil,
              theirs: %{ranges: [">= 1.0.0, < 1.2.3"], patched: ["1.2.3"]},
              status: :theirs_only
            }
          ]
        }
      },
      %Variation{
        id: :pushable,
        description: "A viewer with GitHub linked is offered a push per row the case can write.",
        attributes: %{
          can_push: true,
          rows: [
            %{
              field: :title,
              ours: "Header injection in acme_lib",
              theirs: "Header injection",
              status: :differs
            },
            %{field: :cvss_v4, ours: @vector, theirs: nil, status: :ours_only},
            %{field: :weaknesses, ours: [113, 79], theirs: [113], status: :differs},
            %{
              field: :affected,
              package: "erlang/acme_lib",
              ours: %{ranges: [">= 1.0.0, < 1.2.3"], patched: ["1.2.3"]},
              theirs: %{ranges: ["< 1.2.3"], patched: ["1.2.3"]},
              status: :differs
            }
          ]
        }
      },
      %Variation{
        id: :busy,
        description: "While a request to GitHub runs, every pull and push is held.",
        attributes: %{
          can_pull: true,
          can_push: true,
          busy: true,
          rows: [
            %{
              field: :title,
              ours: "Header injection in acme_lib",
              theirs: "Header injection",
              status: :differs
            },
            %{field: :cvss_v4, ours: nil, theirs: @vector, status: :theirs_only},
            %{field: :weaknesses, ours: [113, 79], theirs: [113], status: :differs}
          ]
        }
      },
      %Variation{
        id: :in_step,
        description: "Nothing to reconcile.",
        attributes: %{
          rows: [
            %{
              field: :title,
              ours: "Header injection in acme_lib",
              theirs: "Header injection in acme_lib",
              status: :same
            },
            %{field: :cvss_v4, ours: nil, theirs: nil, status: :same},
            %{field: :weaknesses, ours: [113], theirs: [113], status: :same},
            %{
              field: :credits,
              ours: [%{login: "alice", name: "Alice Example", roles: [:finder]}],
              theirs: [%{login: "alice", name: "alice", roles: [:finder]}],
              status: :same
            },
            %{
              field: :affected,
              package: "erlang/acme_lib",
              ours: %{ranges: [">= 1.0.0, < 1.2.3"], patched: ["1.2.3"]},
              theirs: %{ranges: [">= 1.0.0, < 1.2.3"], patched: ["1.2.3"]},
              status: :same
            }
          ]
        }
      }
    ]
  end
end
