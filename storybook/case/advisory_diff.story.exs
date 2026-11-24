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

  defp access(name, login, on_case, github, opts \\ []) do
    %{
      row_id: "access-#{login || name |> String.downcase() |> String.replace(" ", "-")}",
      name: name,
      login: login,
      user_id: "user-#{name}",
      case: on_case,
      github: github,
      grant?: Keyword.get(opts, :grant?, false),
      offer: Keyword.get(opts, :offer)
    }
  end

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
              ours: "The inets HTTP server allocates memory without limit.",
              theirs: "The inets HTTP server allocates without limit.",
              status: :differs
            },
            %{field: :solutions, ours: "Upgrade to 29.0.6.", theirs: nil, status: :ours_only},
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
        id: :sections,
        description:
          "Each description section is its own row. Content outside every section shows as a " <>
            "warning with its heading. Impact pushes but never pulls.",
        attributes: %{
          can_pull: true,
          can_push: true,
          rows: [
            %{
              field: :description,
              ours: "acme_lib passes user input into response headers.",
              theirs: "acme_lib passes user input into response headers.",
              status: :same
            },
            %{
              field: :details,
              ours: nil,
              theirs: "The header value is not escaped before it is written.",
              status: :theirs_only
            },
            %{
              field: :impact,
              ours: "An attacker can split HTTP responses.",
              theirs: "Response splitting.",
              status: :differs
            },
            %{
              field: :unmapped,
              ours: nil,
              theirs: [
                %{heading: nil, body: "Reported through the bug bounty."},
                %{heading: "## Timeline", body: "* 2026-11-01 reported\n* 2026-11-20 fixed"}
              ],
              status: :unmapped
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
        id: :gh,
        description:
          "A POC on a repository without the App pushes, and reads again and pulls, with gh. " <>
            "The pull from the stored copy stays.",
        attributes: %{
          can_pull: true,
          gh_pull: true,
          gh_push: true,
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
        id: :access,
        description:
          "Who has access on either side. A POC adds an assignee on GitHub and gives a " <>
            "GitHub collaborator access to the case.",
        attributes: %{
          rows: [
            %{field: :title, ours: "Header injection", theirs: "Header injection", status: :same}
          ],
          access: [
            access("Lukas Larsson", "garazdawi", :assigned, ["collaborator", "owner"]),
            access("Bram", "voltone", :assigned, [], offer: :app),
            access("Peter Ullrich", "PJUllrich", :invited, []),
            access("A hex.pm user", nil, :assigned, []),
            access("kikofernandez", "kikofernandez", nil, ["team security"], grant?: true)
          ]
        }
      },
      %Variation{
        id: :access_gh,
        description:
          "Where the App is not installed a POC adds with gh. The organization's owners are " <>
            "not readable with the viewer's GitHub account.",
        attributes: %{
          rows: [],
          access: [
            access("Bram", "voltone", :assigned, :unknown, offer: :gh),
            access("Eric Meadows-Jönsson", "ericmj", :assigned, ["collaborator"])
          ]
        }
      },
      %Variation{
        id: :access_loading,
        description: "While GitHub is asked who sees the advisory, and for a viewer who may change neither side.",
        attributes: %{
          rows: [],
          access: [
            access("Bram", "voltone", :assigned, :loading),
            access("A hex.pm user", nil, :assigned, [])
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
