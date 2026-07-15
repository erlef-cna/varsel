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

    assert derivation["intro"] == %{"sha" => @intro_sha, "tag" => "v0.1.0", "version" => "0.1.0"}
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

  test "multi-branch fixes derive changes[] chains", %{poc: poc, case: case_record} do
    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.0.0"],
      {@repo, @fix_sha} => ["v2.1.0", "v2.2.0"],
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

    # Newest release line first, matching gen-affected's ordering.
    assert derivation["channels"][channels[:hex].id]["versions"] == [
             %{
               "version" => "1.0.0",
               "lessThan" => "*",
               "status" => "affected",
               "versionType" => "semver",
               "changes" => [
                 %{"at" => "2.1.0", "status" => "unaffected"},
                 %{"at" => "1.5.3", "status" => "unaffected"}
               ]
             }
           ]

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

    # cpe chain: [1.0.0, 1.5.3) then [1.6.0, 2.1.0).
    assert derivation["cpe_matches"] == [
             %{"versionStartIncluding" => "1.0.0", "versionEndExcluding" => "1.5.3"},
             %{"versionStartIncluding" => "1.6.0", "versionEndExcluding" => "2.1.0"}
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
    StubGitBackend.stub_tags(%{{@repo, @fix_sha} => ["v2.0.0"]})

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
    assert issue =~ "cannot resolve commit #{@intro_sha}"
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
        repo_url: otp_repo,
        default_status: :unknown
      })

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

    StubGitBackend.stub_tags(%{
      {otp_repo, @intro_sha} => ["OTP-26.0", "OTP-27.0"],
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

    # ssh's own versions, resolved through otp_versions.table.
    assert derivation["channels"][otp_channel.id]["versions"] == [
             %{
               "version" => "5.0",
               "lessThan" => "*",
               "status" => "affected",
               "versionType" => "otp",
               "changes" => [
                 %{"at" => "5.2.3.4", "status" => "unaffected"},
                 %{"at" => "5.1.4.9", "status" => "unaffected"}
               ]
             }
           ]

    # The implicit git entry carries the OTP release block plus the git SHA block.
    assert [otp_block, git_block] = derivation["git"]["versions"]

    assert otp_block == %{
             "version" => "26.0",
             "lessThan" => "*",
             "status" => "affected",
             "versionType" => "otp",
             "changes" => [
               %{"at" => "27.3.4.1", "status" => "unaffected"},
               %{"at" => "26.2.5.13", "status" => "unaffected"}
             ]
           }

    assert git_block["versionType"] == "git"
    assert git_block["version"] == @intro_sha
  end

  test "OCI channels repeat the range per tag flavor", %{poc: poc, case: case_record} do
    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.9.0-rc1"],
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
