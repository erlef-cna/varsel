# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.DerivationTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.Cases.Derivation
  alias Varsel.Cases.Derivation.OtpVersionsTable
  alias Varsel.Fixtures
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/acme/acme_lib"
  @intro_sha String.duplicate("1", 40)
  @fix_sha String.duplicate("2", 40)
  @fix_sha_backport String.duplicate("3", 40)

  setup do
    poc = Fixtures.register_user("derivation_poc", :poc)
    case_record = Fixtures.open_case(poc)
    %{poc: poc, case: case_record}
  end

  defp package_with_channels(poc, case_record, channels, events) do
    package = Fixtures.add_affected_package(poc, case_record, %{repo_url: @repo})

    channels =
      Map.new(channels, fn {type, attrs} ->
        channel =
          Cases.add_package_channel!(
            Map.merge(
              %{case_id: case_record.id, affected_package_id: package.id, purl_type: type},
              attrs
            ),
            actor: poc
          )

        {type, channel}
      end)

    Enum.each(events, fn attrs ->
      Cases.add_version_event!(
        Map.merge(%{case_id: case_record.id, affected_package_id: package.id}, attrs),
        actor: poc
      )
    end)

    {Ash.load!(package, [:channels, :version_events], authorize?: false), channels}
  end

  test "single fix: hex + git channels derive bounded ranges", %{poc: poc, case: case_record} do
    # intro predates every release, so it is contained by all of them; the fix
    # only landed in v2.10.0. affected = {0.1.0, 1.0.0} -> one range [0.1.0, 2.10.0).
    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v0.1.0", "v1.0.0", "v2.10.0"],
      {@repo, @fix_sha} => ["v2.10.0"]
    })

    {package, channels} =
      package_with_channels(
        poc,
        case_record,
        [{:hex, %{name: "acme_lib"}}],
        [
          %{event: :introduced, commit_sha: @intro_sha},
          %{event: :fixed, commit_sha: @fix_sha}
        ]
      )

    assert {:ok, derivation} = Derivation.derive(package)

    assert derivation["issues"] == []

    assert derivation["channels"][channels[:hex].id]["versions"] == [
             %{
               "version" => "0.1.0",
               "lessThan" => "2.10.0",
               "status" => "affected",
               "versionType" => "semver"
             }
           ]

    # The git/forge entry derives implicitly from the package's repo_url.
    assert derivation["git"]["versions"] == [
             %{
               "version" => @intro_sha,
               "lessThan" => @fix_sha,
               "status" => "affected",
               "versionType" => "git"
             }
           ]

    assert derivation["cpe_matches"] == [
             %{"versionStartIncluding" => "0.1.0", "versionEndExcluding" => "2.10.0"}
           ]
  end

  test "multi-branch fixes cut two bounded ranges", %{poc: poc, case: case_record} do
    # The intro predates every release, so it is contained everywhere. The 1.x
    # branch was fixed at v1.5.3 but that fix was NOT forward-ported, so the 2.x
    # line is re-affected until v2.1.0 fixes it. On the flat timeline that yields
    # two separate affected runs: [1.0.0, 1.5.3) and [2.0.0, 2.1.0).
    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.0.0", "v1.5.3", "v2.0.0", "v2.1.0"],
      {@repo, @fix_sha} => ["v2.1.0"],
      {@repo, @fix_sha_backport} => ["v1.5.3"]
    })

    {package, channels} =
      package_with_channels(
        poc,
        case_record,
        [{:hex, %{name: "acme_lib"}}],
        [
          %{event: :introduced, commit_sha: @intro_sha},
          %{event: :fixed, commit_sha: @fix_sha},
          %{event: :fixed, commit_sha: @fix_sha_backport}
        ]
      )

    assert {:ok, derivation} = Derivation.derive(package)

    # Two separate bounded ranges, ascending on the flat timeline.
    assert derivation["channels"][channels[:hex].id]["versions"] == [
             %{
               "version" => "1.0.0",
               "lessThan" => "1.5.3",
               "status" => "affected",
               "versionType" => "semver"
             },
             %{
               "version" => "2.0.0",
               "lessThan" => "2.1.0",
               "status" => "affected",
               "versionType" => "semver"
             }
           ]

    # SHAs are not linearly orderable, so multiple fixes stay a changes[] chain.
    assert derivation["git"]["versions"] == [
             %{
               "version" => @intro_sha,
               "lessThan" => "*",
               "status" => "affected",
               "versionType" => "git",
               "changes" => [
                 %{"at" => @fix_sha, "status" => "unaffected"},
                 %{"at" => @fix_sha_backport, "status" => "unaffected"}
               ]
             }
           ]

    assert derivation["cpe_matches"] == [
             %{"versionStartIncluding" => "1.0.0", "versionEndExcluding" => "1.5.3"},
             %{"versionStartIncluding" => "2.0.0", "versionEndExcluding" => "2.1.0"}
           ]
  end

  test "a fix with no containing release is pending", %{poc: poc, case: case_record} do
    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.0.0"],
      {@repo, @fix_sha} => []
    })

    {package, channels} =
      package_with_channels(
        poc,
        case_record,
        [{:hex, %{name: "acme_lib"}}],
        [
          %{event: :introduced, commit_sha: @intro_sha},
          %{event: :fixed, commit_sha: @fix_sha}
        ]
      )

    assert {:ok, derivation} = Derivation.derive(package)

    # The version channel falls back to an open range and reports the pending fix.
    assert derivation["channels"][channels[:hex].id]["versions"] == [
             %{
               "version" => "1.0.0",
               "lessThan" => "*",
               "status" => "affected",
               "versionType" => "semver"
             }
           ]

    assert derivation["channels"][channels[:hex].id]["pending"] == [@fix_sha]

    # The implicit git entry still bounds on the commit itself.
    assert derivation["git"]["versions"] == [
             %{
               "version" => @intro_sha,
               "lessThan" => @fix_sha,
               "status" => "affected",
               "versionType" => "git"
             }
           ]
  end

  test "an unresolvable commit becomes an issue", %{poc: poc, case: case_record} do
    # The intro is not stubbed, so it resolves to no tag; the universe still needs
    # the fix's release plus an extra tag so the timeline is non-empty.
    StubGitBackend.stub_tags(%{{@repo, @fix_sha} => ["v2.0.0"]})
    StubGitBackend.stub_all_tags(%{@repo => ["v1.0.0"]})

    {package, _channels} =
      package_with_channels(
        poc,
        case_record,
        [{:hex, %{name: "acme_lib"}}],
        [
          %{event: :introduced, commit_sha: @intro_sha},
          %{event: :fixed, commit_sha: @fix_sha}
        ]
      )

    assert {:ok, derivation} = Derivation.derive(package)
    assert [issue] = derivation["issues"]
    assert issue =~ "the introducing commit is contained in no release tag"
  end

  test "channel-scoped explicit events drive a hosted channel", %{poc: poc, case: case_record} do
    package =
      Fixtures.add_affected_package(poc, case_record, %{repo_url: nil, product: "acme.example"})

    channel =
      Cases.add_package_channel!(
        %{case_id: case_record.id, affected_package_id: package.id, purl_type: :hosted},
        actor: poc
      )

    for attrs <- [
          %{event: :introduced, version: "2025-10-01", package_channel_id: channel.id},
          %{event: :fixed, version: "2026-01-19", package_channel_id: channel.id}
        ] do
      Cases.add_version_event!(
        Map.merge(%{case_id: case_record.id, affected_package_id: package.id}, attrs),
        actor: poc
      )
    end

    package = Ash.load!(package, [:channels, :version_events], authorize?: false)
    assert {:ok, derivation} = Derivation.derive(package)

    assert derivation["channels"][channel.id]["versions"] == [
             %{
               "version" => "2025-10-01",
               "lessThan" => "2026-01-19",
               "status" => "affected",
               "versionType" => "date"
             }
           ]
  end

  test "OTP packages resolve per-application versions and emit both blocks on the git channel", %{
    poc: poc,
    case: case_record
  } do
    otp_repo = "https://github.com/erlang/otp"

    Req.Test.stub(OtpVersionsTable, fn conn ->
      Plug.Conn.send_resp(conn, 200, """
      OTP-27.3.4.1 : ssh-5.2.3.4 stdlib-6.2.2.1 # erts-15.2.7 :
      OTP-27.0 : ssh-5.2 stdlib-6.0 # erts-15.0 :
      OTP-26.2.5.13 : ssh-5.1.4.9 stdlib-5.2.3.4 # erts-14.2.5 :
      OTP-26.0 : ssh-5.0 stdlib-5.0 # erts-14.0 :
      """)
    end)

    on_exit(&OtpVersionsTable.reset/0)

    package =
      Fixtures.add_affected_package(poc, case_record, %{
        vendor: "Erlang",
        product: "OTP",
        repo_url: otp_repo
      })

    release_channel =
      Cases.add_package_channel!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          purl_type: :sid,
          namespace: "erlang.org",
          name: "otp"
        },
        actor: poc
      )

    otp_channel =
      Cases.add_package_channel!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          purl_type: :otp,
          name: "ssh"
        },
        actor: poc
      )

    # The intro predates every release; the 27.x line is fixed at OTP-27.3.4.1 and
    # the 26.x line backported to OTP-26.2.5.13. Neither fix is on the other line,
    # so both maintenance lines stay affected up to their own fix -> two runs.
    StubGitBackend.stub_tags(%{
      {otp_repo, @intro_sha} => ["OTP-26.0", "OTP-26.2.5.13", "OTP-27.0", "OTP-27.3.4.1"],
      {otp_repo, @fix_sha} => ["OTP-27.3.4.1"],
      {otp_repo, @fix_sha_backport} => ["OTP-26.2.5.13"]
    })

    for attrs <- [
          %{event: :introduced, commit_sha: @intro_sha},
          %{event: :fixed, commit_sha: @fix_sha},
          %{event: :fixed, commit_sha: @fix_sha_backport}
        ] do
      Cases.add_version_event!(
        Map.merge(%{case_id: case_record.id, affected_package_id: package.id}, attrs),
        actor: poc
      )
    end

    package = Ash.load!(package, [:channels, :version_events], authorize?: false)
    assert {:ok, derivation} = Derivation.derive(package)

    # ssh's own versions, resolved through otp_versions.table, as bounded ranges.
    assert derivation["channels"][otp_channel.id]["versions"] == [
             %{
               "version" => "5.0",
               "lessThan" => "5.1.4.9",
               "status" => "affected",
               "versionType" => "otp"
             },
             %{
               "version" => "5.2",
               "lessThan" => "5.2.3.4",
               "status" => "affected",
               "versionType" => "otp"
             }
           ]

    # The sid release channel carries the OTP release versions (bare, bounded).
    assert derivation["channels"][release_channel.id]["versions"] == [
             %{
               "version" => "26.0",
               "lessThan" => "26.2.5.13",
               "status" => "affected",
               "versionType" => "otp"
             },
             %{
               "version" => "27.0",
               "lessThan" => "27.3.4.1",
               "status" => "affected",
               "versionType" => "otp"
             }
           ]

    # The implicit git entry is commit SHAs alone — no release versions.
    assert [git_block] = derivation["git"]["versions"]
    assert git_block["versionType"] == "git"
    assert git_block["version"] == @intro_sha
  end

  test "pkg:otp channels of non-OTP repos derive semver ranges from the repo tags", %{
    poc: poc,
    case: case_record
  } do
    elixir_repo = "https://github.com/elixir-lang/elixir"

    # Elixir uses semver tags. intro predates every release; fix lands in v1.20.1.
    StubGitBackend.stub_tags(%{
      {elixir_repo, @intro_sha} => ["v1.5.0", "v1.6.0", "v1.20.1"],
      {elixir_repo, @fix_sha} => ["v1.20.1"]
    })

    package =
      Fixtures.add_affected_package(poc, case_record, %{
        vendor: "elixir-lang",
        product: "elixir",
        repo_url: elixir_repo
      })

    channel =
      Cases.add_package_channel!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          purl_type: :otp,
          name: "elixir"
        },
        actor: poc
      )

    for attrs <- [
          %{event: :introduced, commit_sha: @intro_sha},
          %{event: :fixed, commit_sha: @fix_sha}
        ] do
      Cases.add_version_event!(
        Map.merge(%{case_id: case_record.id, affected_package_id: package.id}, attrs),
        actor: poc
      )
    end

    package = Ash.load!(package, [:channels, :version_events], authorize?: false)
    assert {:ok, derivation} = Derivation.derive(package)

    # Elixir's applications version with Elixir itself: no otp_versions.table,
    # plain semver boundaries from the repository tags.
    assert derivation["channels"][channel.id]["versions"] == [
             %{
               "version" => "1.5.0",
               "lessThan" => "1.20.1",
               "status" => "affected",
               "versionType" => "semver"
             }
           ]

    # The implicit git entry stays a pure git-SHA range (no OTP release block).
    assert [git_block] = derivation["git"]["versions"]
    assert git_block["versionType"] == "git"
    assert git_block["version"] == @intro_sha
    assert git_block["lessThan"] == @fix_sha
  end

  test "OCI channels repeat the range per tag flavor", %{poc: poc, case: case_record} do
    # intro predates every release; fix lands in v1.15.4 -> one range
    # [1.9.0-rc1, 1.15.4), repeated once per tag flavor.
    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.9.0-rc1", "v1.15.4"],
      {@repo, @fix_sha} => ["v1.15.4"]
    })

    {package, channels} =
      package_with_channels(
        poc,
        case_record,
        [
          {:oci,
           %{
             name: "acme_lib",
             qualifiers: %{"repository_url" => "ghcr.io/acme"},
             tag_suffixes: ["elixir", "erlang"]
           }}
        ],
        [
          %{event: :introduced, commit_sha: @intro_sha},
          %{event: :fixed, commit_sha: @fix_sha}
        ]
      )

    assert {:ok, derivation} = Derivation.derive(package)

    assert derivation["channels"][channels[:oci].id]["versions"] == [
             %{
               "version" => "v1.9.0-rc1-elixir",
               "lessThan" => "v1.15.4-elixir",
               "status" => "affected",
               "versionType" => "other"
             },
             %{
               "version" => "v1.9.0-rc1-erlang",
               "lessThan" => "v1.15.4-erlang",
               "status" => "affected",
               "versionType" => "other"
             }
           ]
  end
end
