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
          cvss_v4: nil,
          weaknesses: [%CaseWeakness{cwe_id: 113}],
          credits: [
            %CaseCredit{
              name: "Alice Example",
              credit_type: :finder,
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

  test "the description compares the case's advisory text with the advisory's" do
    cna = %{
      "descriptions" => [
        %{
          "lang" => "en",
          "value" => "plain",
          "supportingMedia" => [
            %{
              "base64" => false,
              "type" => "text/markdown",
              "value" => "acme_lib passes user input\ninto response headers."
            }
          ]
        }
      ]
    }

    preview = %Preview.Result{cve_record: %{"containers" => %{"cna" => cna}}}

    advisory =
      Map.put(
        hex_advisory(),
        "description",
        "### Summary\r\n\r\nacme_lib passes user input into response headers."
      )

    rows = Diff.rows(case_record(%{preview: preview}), advisory)
    assert %{status: :same, ours: "### Summary\n\nacme_lib" <> _} = one(rows, :description)
    refute Diff.pullable?(one(rows, :description))
    refute Diff.pushable?(one(rows, :description))

    rows = Diff.rows(case_record(%{preview: preview}), hex_advisory())
    assert one(rows, :description).status == :differs
    refute Diff.pullable?(one(rows, :description))
    assert Diff.pushable?(one(rows, :description))
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

    rows = Diff.rows(case_record(%{cvss_v4: vector}), hex_advisory())
    assert %{status: :ours_only, ours: @vector, theirs: nil} = one(rows, :cvss_v4)

    rows = Diff.rows(case_record(%{cvss_v4: nil, title: nil}), otp_advisory())
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
              credit_type: :reporter,
              handles: [%Handle{strategy: :github, username: "GARAZDAWI"}]
            },
            %CaseCredit{name: "Whaileee", credit_type: :remediation_reviewer, handles: []}
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
              credit_type: :analyst,
              handles: [%Handle{strategy: :github, username: "garazdawi"}]
            },
            %CaseCredit{
              name: "Lukas",
              credit_type: :reporter,
              handles: [%Handle{strategy: :github, username: "garazdawi"}]
            },
            %CaseCredit{
              name: "W",
              credit_type: :remediation_reviewer,
              handles: [%Handle{strategy: :github, username: "Whaileee"}]
            },
            %CaseCredit{name: "Nobody Here", credit_type: :finder, handles: []}
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
              credit_type: :analyst,
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
