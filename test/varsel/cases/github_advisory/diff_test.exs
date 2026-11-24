# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.DiffTest do
  use ExUnit.Case, async: true

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case
  alias Varsel.Cases.Case.Calculations.Preview
  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseCredit.Handle
  alias Varsel.Cases.CaseMetric
  alias Varsel.Cases.CaseWeakness
  alias Varsel.Cases.GitHubAdvisory.Diff
  alias Varsel.Cases.PackageChannel
  alias Varsel.Types.CVSS

  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"

  defp case_record(overrides) do
    struct!(
      Case,
      Map.merge(
        %{
          title: "Header injection in acme_lib",
          description_md: "acme_lib passes user input into response headers.",
          cve_id: nil,
          general_metric: nil,
          weaknesses: [%CaseWeakness{cwe_id: 113}],
          credits: [
            %CaseCredit{
              name: "Alice Example",
              credit_types: [:finder],
              handles: [%Handle{strategy: :github, username: "alice"}]
            }
          ],
          affected_packages: []
        },
        overrides
      )
    )
  end

  defp package_with(product, entries) do
    channels =
      Enum.map(entries, fn {channel, ranges} -> {%{channel | id: Ash.UUID.generate()}, ranges} end)

    cache =
      Map.new(channels, fn {channel, ranges} -> {channel.id, %{"github_ranges" => ranges}} end)

    %AffectedPackage{
      product: product,
      channels: Enum.map(channels, &elem(&1, 0)),
      derivation_cache: %{"channels" => cache}
    }
  end

  defp hex(name), do: %PackageChannel{purl_type: "hex", name: name}
  defp otp_app(name), do: %PackageChannel{purl_type: "otp", name: name, version_type: :otp}

  defp otp_release,
    do: %PackageChannel{purl_type: "software-id", namespace: "erlang.org", name: "otp", version_type: :otp}

  defp git(namespace, name), do: %PackageChannel{purl_type: "github", namespace: namespace, name: name}

  defp github_range(range, patched), do: %{"vulnerable_version_range" => range, "patched_versions" => patched}

  defp by_field(rows, field), do: Enum.filter(rows, &(&1.field == field))
  defp one(rows, field), do: rows |> by_field(field) |> List.first()

  test "a case matching its advisory has every row the same" do
    packages = [
      package_with("acme_lib", [{hex("acme_lib"), [github_range(">= 1.0.0, < 1.2.3", ["1.2.3"])]}])
    ]

    rows = Diff.rows(case_record(%{affected_packages: packages}), hex_advisory())

    assert Enum.map(rows, &{&1.field, &1.status}) == [
             {:title, :same},
             {:description, :theirs_only},
             {:details, :same},
             {:proof_of_concept, :same},
             {:impact, :same},
             {:workarounds, :same},
             {:configurations, :same},
             {:solutions, :same},
             {:references, :same},
             {:cve_id, :same},
             {:cvss_v4, :same},
             {:weaknesses, :same},
             {:credits, :same},
             {:affected, :same}
           ]

    assert one(rows, :affected) == %{
             field: :affected,
             package: "erlang/acme_lib",
             ours: %{ranges: [">= 1.0.0, < 1.2.3"], patched: ["1.2.3"]},
             theirs: %{ranges: [">= 1.0.0, < 1.2.3"], patched: ["1.2.3"]},
             status: :same
           }
  end

  defp markdown_entry(text) do
    [
      %{
        "lang" => "en",
        "value" => "plain",
        "supportingMedia" => [%{"base64" => false, "type" => "text/markdown", "value" => text}]
      }
    ]
  end

  defp with_cna(cna), do: %{preview: %Preview.Result{cve_record: %{"containers" => %{"cna" => cna}}}}

  test "each description section compares as its own row" do
    cna = %{
      "descriptions" => markdown_entry("acme_lib passes user input\ninto response headers."),
      "solutions" => markdown_entry("Upgrade to 1.2.3."),
      "references" => [%{"url" => "https://example.com/fix"}]
    }

    advisory =
      Map.put(
        hex_advisory(),
        "description",
        "### Summary\r\n\r\nacme_lib passes user input into response headers.\r\n\r\n" <>
          "### Details\r\n\r\nThe header value is not escaped.\r\n\r\n" <>
          "### Solutions\r\n\r\nUpgrade to 1.2.4."
      )

    rows = Diff.rows(case_record(with_cna(cna)), advisory)

    assert %{status: :same, ours: "acme_lib passes user input\ninto response headers."} =
             one(rows, :description)

    assert %{status: :theirs_only, theirs: "The header value is not escaped."} =
             one(rows, :details)

    assert Diff.pullable?(one(rows, :details))
    refute Diff.pushable?(one(rows, :details))

    assert %{status: :differs, ours: "Upgrade to 1.2.3.", theirs: "Upgrade to 1.2.4."} =
             one(rows, :solutions)

    assert Diff.pullable?(one(rows, :solutions))
    assert Diff.pushable?(one(rows, :solutions))

    assert %{status: :ours_only} = one(rows, :references)
    assert Diff.pushable?(one(rows, :references))

    assert one(rows, :proof_of_concept).status == :same
    refute one(rows, :unmapped)
  end

  test "impact and references are never pulled" do
    advisory =
      Map.put(
        hex_advisory(),
        "description",
        "### Impact\n\nAn attacker splits responses.\n\n### References\n\n* https://example.com"
      )

    rows = Diff.rows(case_record(with_cna(%{})), advisory)

    assert %{status: :theirs_only} = one(rows, :impact)
    refute Diff.pullable?(one(rows, :impact))
    assert %{status: :theirs_only} = one(rows, :references)
    refute Diff.pullable?(one(rows, :references))
  end

  test "content outside every section is one unmapped row" do
    advisory =
      Map.put(
        hex_advisory(),
        "description",
        "Reported by a scanner.\n\n### Summary\n\nacme_lib passes user input.\n\n## Timeline\n\nMarch."
      )

    rows = Diff.rows(case_record(with_cna(%{})), advisory)

    assert one(rows, :unmapped) == %{
             field: :unmapped,
             ours: nil,
             theirs: [
               %{heading: nil, body: "Reported by a scanner."},
               %{heading: "## Timeline", body: "March."}
             ],
             status: :unmapped
           }

    refute Diff.pullable?(one(rows, :unmapped))
    refute Diff.pushable?(one(rows, :unmapped))
  end

  test "the title differs only when the words do" do
    rows = Diff.rows(case_record(%{title: "Header  injection in\nacme_lib"}), hex_advisory())
    assert one(rows, :title).status == :same

    rows = Diff.rows(case_record(%{title: "Something else"}), hex_advisory())

    assert %{status: :differs, ours: "Something else", theirs: "Header injection in acme_lib"} =
             one(rows, :title)
  end

  test "a value one side lacks is that side's alone" do
    {:ok, vector} = CVSS.cast_input(@vector, version: [:v4])

    metric = %CaseMetric{scenario: "GENERAL", cvss_v4: vector}
    rows = Diff.rows(case_record(%{general_metric: metric}), hex_advisory())
    assert %{status: :ours_only, ours: @vector, theirs: nil} = one(rows, :cvss_v4)

    rows = Diff.rows(case_record(%{general_metric: nil, title: nil}), otp_advisory())
    assert %{status: :theirs_only, theirs: @vector} = one(rows, :cvss_v4)
    assert one(rows, :title).status == :theirs_only
  end

  test "CWEs and credits compare as sets" do
    rows =
      Diff.rows(
        case_record(%{
          weaknesses: [%CaseWeakness{cwe_id: 770}, %CaseWeakness{cwe_id: 400}],
          credits: [
            %CaseCredit{
              name: "Lukas",
              credit_types: [:reporter],
              handles: [%Handle{strategy: :github, username: "GARAZDAWI"}]
            },
            %CaseCredit{name: "Whaileee", credit_types: [:remediation_reviewer], handles: []}
          ]
        }),
        otp_advisory()
      )

    assert %{status: :differs, ours: [770, 400], theirs: [770]} = one(rows, :weaknesses)

    # Whaileee has no GitHub account here, so GitHub's credit for that login is missing.
    assert %{status: :differs, theirs: [%{login: "garazdawi"}, %{login: "whaileee"}]} =
             one(rows, :credits)
  end

  test "credits compare per person, and a person's extra roles here are no difference" do
    rows =
      Diff.rows(
        case_record(%{
          credits: [
            %CaseCredit{
              name: "Lukas",
              credit_types: [:analyst],
              handles: [%Handle{strategy: :github, username: "garazdawi"}]
            },
            %CaseCredit{
              name: "Lukas",
              credit_types: [:reporter],
              handles: [%Handle{strategy: :github, username: "garazdawi"}]
            },
            %CaseCredit{
              name: "W",
              credit_types: [:remediation_reviewer],
              handles: [%Handle{strategy: :github, username: "Whaileee"}]
            },
            %CaseCredit{name: "Nobody Here", credit_types: [:finder], handles: []}
          ]
        }),
        otp_advisory()
      )

    assert %{status: :same, ours: ours} = one(rows, :credits)

    assert ours == [
             %{login: "garazdawi", name: "Lukas", roles: [:analyst, :reporter]},
             %{login: "whaileee", name: "W", roles: [:remediation_reviewer]},
             %{login: nil, name: "Nobody Here", roles: [:finder]}
           ]
  end

  test "a person whose GitHub role is missing here differs" do
    rows =
      Diff.rows(
        case_record(%{
          credits: [
            %CaseCredit{
              name: "Alice",
              credit_types: [:analyst],
              handles: [%Handle{strategy: :github, username: "alice"}]
            }
          ]
        }),
        hex_advisory()
      )

    assert one(rows, :credits).status == :differs
    assert Diff.pullable?(one(rows, :credits))
    refute Diff.pushable?(one(rows, :credits))
  end

  test "affected entries match a channel by ecosystem and name and compare derived ranges" do
    packages = [
      package_with("OTP", [
        {otp_release(), [github_range(">= 17.0", ["27.3.4.17", "28.5.0.6", "29.0.6"])]},
        {otp_app("inets"), [github_range(">= 5.10", ["9.3.2.7", "9.6.2.3", "9.7.3"])]},
        {git("erlang", "otp"), []}
      ])
    ]

    rows = Diff.rows(case_record(%{affected_packages: packages}), otp_advisory())

    assert Enum.map(by_field(rows, :affected), &{&1.package, &1.status}) == [
             {"OTP", :same},
             {"otp/inets", :differs}
           ]

    assert %{
             ours: %{ranges: [">= 5.10"], patched: ["9.3.2.7", "9.6.2.3", "9.7.3"]},
             theirs: %{ranges: [">= 5.10"], patched: ["9.7.2", "9.6.2.3", "9.3.2.7"]}
           } = Enum.at(by_field(rows, :affected), 1)
  end

  test "a channel the advisory does not name is ours alone, unless it derived nothing" do
    packages = [
      package_with("acme_lib", [
        {hex("acme_lib"), [github_range(">= 1.0.0, < 1.2.3", ["1.2.3"])]},
        {hex("acme_extra"), [github_range("< 0.3.0", ["0.3.0"])]},
        {git("acme", "acme_lib"), []}
      ])
    ]

    rows = Diff.rows(case_record(%{affected_packages: packages}), hex_advisory())

    assert Enum.map(by_field(rows, :affected), &{&1.package, &1.status}) == [
             {"erlang/acme_lib", :same},
             {"hex/acme_extra", :ours_only}
           ]
  end

  test "an oci entry matches the image channel by its repository_url" do
    image = %PackageChannel{
      purl_type: "oci",
      name: "acme_lib",
      qualifiers: %{"repository_url" => "ghcr.io/acme/acme_lib"}
    }

    packages = [
      package_with("acme_lib", [
        {hex("acme_lib"), [github_range(">= 1.0.0, < 1.2.3", ["1.2.3"])]},
        {image, [github_range(">= 1.0.0, < 1.2.3", ["1.2.3"])]}
      ])
    ]

    entry = %{
      "package" => %{"ecosystem" => "oci", "name" => "ghcr.io/acme/acme_lib"},
      "patched_versions" => "1.2.3",
      "vulnerable_functions" => [],
      "vulnerable_version_range" => ">=1.0.0,<1.2.3"
    }

    advisory = Map.update!(hex_advisory(), "vulnerabilities", &(&1 ++ [entry]))
    rows = Diff.rows(case_record(%{affected_packages: packages}), advisory)

    assert Enum.map(by_field(rows, :affected), &{&1.package, &1.status}) == [
             {"erlang/acme_lib", :same},
             {"oci/ghcr.io/acme/acme_lib", :same}
           ]
  end

  for ecosystem <- ["", "other"] do
    test "an entry with ecosystem #{inspect(ecosystem)} matches a service channel by its domain" do
      service = %PackageChannel{kind: :service, domain: "hex.pm", version_type: :date}

      packages = [
        package_with("hexpm", [
          {service, [github_range(">= 2016-02-23, < 2026-11-23", ["2026-11-23"])]}
        ])
      ]

      entry = %{
        "package" => %{"ecosystem" => unquote(ecosystem), "name" => "hex.pm"},
        "patched_versions" => "2026-11-23",
        "vulnerable_functions" => [],
        "vulnerable_version_range" => ">= 2016-02-23, < 2026-11-23"
      }

      advisory = Map.put(hex_advisory(), "vulnerabilities", [entry])
      rows = Diff.rows(case_record(%{affected_packages: packages}), advisory)

      assert Enum.map(by_field(rows, :affected), &{&1.package, &1.status}) == [{"hex.pm", :same}]
    end
  end

  test "the entries that name one channel compare as one row" do
    packages = [
      package_with("acme_lib", [
        {hex("acme_lib"),
         [
           github_range(">= 1.0.0, < 1.2.3", ["1.2.3"]),
           github_range(">= 2.0.0, < 2.0.4", ["2.0.4"])
         ]}
      ])
    ]

    entry = %{
      "package" => %{"ecosystem" => "erlang", "name" => "acme_lib"},
      "patched_versions" => "2.0.4",
      "vulnerable_version_range" => ">= 2.0.0, < 2.0.4"
    }

    advisory = Map.update!(hex_advisory(), "vulnerabilities", &(&1 ++ [entry]))
    rows = Diff.rows(case_record(%{affected_packages: packages}), advisory)

    assert [
             %{
               package: "erlang/acme_lib",
               status: :same,
               theirs: %{
                 ranges: [">= 1.0.0, < 1.2.3", ">= 2.0.0, < 2.0.4"],
                 patched: ["1.2.3", "2.0.4"]
               }
             }
           ] = by_field(rows, :affected)
  end

  test "a channel with a purl namespace matches the entry named namespace/name" do
    gleam = %PackageChannel{purl_type: "software-id", namespace: "gleam.run", name: "gleam"}
    packages = [package_with("gleam", [{gleam, [github_range(">= 1.0.0, < 1.2.3", ["1.2.3"])]}])]

    advisory =
      Map.put(hex_advisory(), "vulnerabilities", [
        %{
          "package" => %{"ecosystem" => "software-id", "name" => "gleam.run/gleam"},
          "vulnerable_version_range" => ">= 1.0.0, < 1.2.3",
          "patched_versions" => "1.2.3"
        }
      ])

    rows = Diff.rows(case_record(%{affected_packages: packages}), advisory)

    assert Enum.map(by_field(rows, :affected), &{&1.package, &1.status}) == [
             {"software-id/gleam.run/gleam", :same}
           ]
  end

  test "an application of a preset advisory matches the channel spelled as the preset spells it" do
    advisory =
      hex_advisory()
      |> Map.put(
        "html_url",
        "https://github.com/elixir-lang/elixir/security/advisories/GHSA-2cfg-hjmp-qrvw"
      )
      |> Map.put("vulnerabilities", [
        %{
          "package" => %{"ecosystem" => "elixir", "name" => "ExUnit"},
          "vulnerable_version_range" => "< 1.18.0",
          "patched_versions" => "1.18.0"
        }
      ])

    packages = [
      package_with("elixir", [{otp_app("ex_unit"), [github_range("< 1.18.0", ["1.18.0"])]}])
    ]

    rows = Diff.rows(case_record(%{affected_packages: packages}), advisory)

    assert Enum.map(by_field(rows, :affected), &{&1.package, &1.status}) == [
             {"elixir/ExUnit", :same}
           ]
  end

  test "an otp entry of any other advisory matches the channel by its plain name" do
    advisory =
      Map.put(hex_advisory(), "vulnerabilities", [
        %{
          "package" => %{"ecosystem" => "otp", "name" => "Inets"},
          "vulnerable_version_range" => "< 9.7.3",
          "patched_versions" => "9.7.3"
        }
      ])

    packages = [package_with("OTP", [{otp_app("inets"), [github_range("< 9.7.3", ["9.7.3"])]}])]

    rows = Diff.rows(case_record(%{affected_packages: packages}), advisory)

    assert Enum.map(by_field(rows, :affected), &{&1.package, &1.status}) == [{"otp/Inets", :same}]
  end

  test "a channel that derived nothing yet is reported as such, and a package the case lacks as theirs alone" do
    packages = [package_with("acme_lib", [{hex("acme_lib"), []}])]

    rows = Diff.rows(case_record(%{affected_packages: packages}), hex_advisory())
    assert one(rows, :affected).status == :not_derived
    refute Diff.pullable?(one(rows, :affected))
    refute Diff.pushable?(one(rows, :affected))

    rows = Diff.rows(case_record(%{}), hex_advisory())
    assert %{status: :theirs_only, ours: nil} = one(rows, :affected)
    assert Diff.pullable?(one(rows, :affected))
    refute Diff.pushable?(one(rows, :affected))
  end

  test "derived ranges that differ are pushed, never pulled" do
    packages = [
      package_with("acme_lib", [{hex("acme_lib"), [github_range("< 1.2.4", ["1.2.4"])]}])
    ]

    rows = Diff.rows(case_record(%{affected_packages: packages}), hex_advisory())
    assert one(rows, :affected).status == :differs
    refute Diff.pullable?(one(rows, :affected))
    assert Diff.pushable?(one(rows, :affected))
  end

  test "a cached range without patched versions is an open range" do
    packages = [
      package_with("acme_lib", [{hex("acme_lib"), [%{"vulnerable_version_range" => ">= 1.0.0"}]}])
    ]

    rows = Diff.rows(case_record(%{affected_packages: packages}), hex_advisory())

    assert %{status: :differs, ours: %{ranges: [">= 1.0.0"], patched: []}} = one(rows, :affected)
  end

  test "CWEs pull when the advisory has one the case lacks, and push the other way round" do
    rows = Diff.rows(case_record(%{weaknesses: [%CaseWeakness{cwe_id: 79}]}), hex_advisory())
    assert %{status: :differs, ours: [79], theirs: [113]} = one(rows, :weaknesses)
    assert Diff.pullable?(one(rows, :weaknesses))
    assert Diff.pushable?(one(rows, :weaknesses))

    rows =
      Diff.rows(
        case_record(%{weaknesses: [%CaseWeakness{cwe_id: 113}, %CaseWeakness{cwe_id: 79}]}),
        hex_advisory()
      )

    refute Diff.pullable?(one(rows, :weaknesses))
    assert Diff.pushable?(one(rows, :weaknesses))

    rows = Diff.rows(case_record(%{weaknesses: []}), hex_advisory())
    assert one(rows, :weaknesses).status == :theirs_only
    assert Diff.pullable?(one(rows, :weaknesses))
    refute Diff.pushable?(one(rows, :weaknesses))
  end

  test "a CVE ID is never pulled, not even one the case lacks" do
    rows = Diff.rows(case_record(%{cve_id: nil}), otp_advisory())
    assert %{status: :theirs_only, theirs: "CVE-2026-48858"} = one(rows, :cve_id)
    refute Diff.pullable?(one(rows, :cve_id))
    refute Diff.pushable?(one(rows, :cve_id))

    rows = Diff.rows(case_record(%{cve_id: "CVE-2026-1"}), hex_advisory())
    assert one(rows, :cve_id).status == :ours_only
    assert Diff.pushable?(one(rows, :cve_id))
  end
end
