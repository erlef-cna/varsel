# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.EmitTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Derivation.Emit
  alias Varsel.Cases.Derivation.OtpVersionsTable
  alias Varsel.Cases.PackageChannel

  defp range(from, until), do: %{from: from, until: until}

  describe "version_type/1" do
    test "the channel's own type wins over its purl type's default" do
      assert Emit.version_type(%PackageChannel{purl_type: "sid", version_type: :otp}) == :otp
    end

    test "falls back to the purl type's default" do
      assert Emit.version_type(%PackageChannel{purl_type: "hex"}) == :semver
      assert Emit.version_type(%PackageChannel{purl_type: "oci"}) == :other
      assert Emit.version_type(%PackageChannel{purl_type: "github"}) == :git
    end

    test "an unknown purl type versions in semver" do
      assert Emit.version_type(%PackageChannel{purl_type: "brand-new"}) == :semver
    end

    test "a service is always dated" do
      assert Emit.version_type(%PackageChannel{kind: :service, domain: "hex.pm"}) == :date
    end
  end

  describe "channel/3 semver" do
    test "each range is a separate bounded entry, prefix stripped" do
      channel = %PackageChannel{purl_type: "hex", name: "acme", tag_suffixes: []}
      ranges = [range("v1.7.0", "v1.7.22"), range("v1.8.0", "v1.8.6")]

      assert Emit.channel(channel, ranges, []) == %{
               "versions" => [
                 %{
                   "version" => "1.7.0",
                   "lessThan" => "1.7.22",
                   "status" => "affected",
                   "versionType" => "semver"
                 },
                 %{
                   "version" => "1.8.0",
                   "lessThan" => "1.8.6",
                   "status" => "affected",
                   "versionType" => "semver"
                 }
               ],
               "issues" => []
             }
    end

    test "an unbounded range renders lessThan: *" do
      channel = %PackageChannel{purl_type: "hex", name: "acme", tag_suffixes: []}

      assert %{"versions" => [%{"lessThan" => "*"}]} =
               Emit.channel(channel, [range("v1.0.0", :unbounded)], [])
    end

    test "an unknown purl type still derives semver ranges" do
      channel = %PackageChannel{purl_type: "cargo", name: "acme", tag_suffixes: []}

      assert %{"versions" => [%{"version" => "1.2.3", "versionType" => "semver"}]} =
               Emit.channel(channel, [range("v1.2.3", "v1.2.9")], [])
    end
  end

  describe "channel/3 tag decoration" do
    test "repeats each range per flavor" do
      channel = %PackageChannel{
        purl_type: "oci",
        name: "acme",
        tag_prefix: "v",
        tag_suffixes: ["elixir", "erlang"]
      }

      assert Emit.channel(channel, [range("v1.9.0-rc1", "v1.15.4")], []) == %{
               "versions" => [
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
               ],
               "issues" => []
             }
    end

    test "emits bare versions when no prefix is configured" do
      channel = %PackageChannel{purl_type: "oci", name: "acme", tag_prefix: "", tag_suffixes: []}

      assert Emit.channel(channel, [range("v1.2.3", "v1.2.9")], []) == %{
               "versions" => [
                 %{
                   "version" => "1.2.3",
                   "lessThan" => "1.2.9",
                   "status" => "affected",
                   "versionType" => "other"
                 }
               ],
               "issues" => []
             }
    end

    test "a - suffix is the bare flavor alongside real ones" do
      channel = %PackageChannel{
        purl_type: "oci",
        name: "acme",
        tag_prefix: "",
        tag_suffixes: ["-", "special"]
      }

      assert Emit.channel(channel, [range("v1.2.3", "v1.2.9")], []) == %{
               "versions" => [
                 %{
                   "version" => "1.2.3",
                   "lessThan" => "1.2.9",
                   "status" => "affected",
                   "versionType" => "other"
                 },
                 %{
                   "version" => "1.2.3-special",
                   "lessThan" => "1.2.9-special",
                   "status" => "affected",
                   "versionType" => "other"
                 }
               ],
               "issues" => []
             }
    end

    test "an unbounded range stays open per flavor" do
      channel = %PackageChannel{
        purl_type: "oci",
        name: "acme",
        tag_prefix: "v",
        tag_suffixes: ["-", "special"]
      }

      assert %{"versions" => versions} =
               Emit.channel(channel, [range("v1.2.3", :unbounded)], [])

      assert [
               %{"version" => "v1.2.3", "lessThan" => "*"},
               %{"version" => "v1.2.3-special", "lessThan" => "*"}
             ] = versions
    end

    test "applies to any purl type, not just oci" do
      channel = %PackageChannel{purl_type: "hex", name: "acme", tag_prefix: "v", tag_suffixes: []}

      assert %{"versions" => [%{"version" => "v1.2.3", "versionType" => "semver"}]} =
               Emit.channel(channel, [range("1.2.3", "1.2.9")], [])
    end
  end

  describe "channel/3 otp app translation" do
    setup do
      Req.Test.stub(OtpVersionsTable, fn conn ->
        Plug.Conn.send_resp(conn, 200, """
        OTP-27.3.4.3 : ssh-5.2.3.4 stdlib-6.2.2.1 tftp-1.2.1 :
        OTP-27.0 : ssh-5.2 stdlib-6.0 tftp-1.2 :
        OTP-26.2.5.15 : ssh-5.1.4.12 stdlib-5.2.3.4 :
        OTP-26.0 : ssh-5.0 stdlib-5.0 :
        """)
      end)

      on_exit(&OtpVersionsTable.reset/0)
    end

    # `tftp` split out of `inets` and first ships in OTP-27.0, so a span opening
    # before it existed opens at its first version.
    test "a lower bound before the app existed falls forward to its first version" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "tftp",
        version_type: :otp,
        tag_suffixes: []
      }

      assert %{"versions" => [entry], "issues" => []} =
               Emit.channel(channel, [range("OTP-26.0", "OTP-27.3.4.3")], [])

      assert entry["version"] == "1.2"
      assert entry["lessThan"] == "1.2.1"
    end

    # The release carries no `tftp`, so it states nothing about it. Falling
    # forward here would name a version as the fix that never carried one.
    test "an upper bound in a release without the app is an issue, not a later version" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "tftp",
        version_type: :otp,
        tag_suffixes: []
      }

      assert Emit.channel(channel, [range("OTP-26.0", "OTP-26.2.5.15")], []) == %{
               "versions" => [],
               "issues" => ["cannot resolve tftp's version for a range"]
             }
    end

    test "a fix transition in a release without the app is an issue too" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "tftp",
        version_type: :otp,
        tag_suffixes: []
      }

      boundaries = %{introduced: "26.0", fixed: ["26.2.5.15", "27.3.4.3"], open?: true}

      assert Emit.channel(channel, [range("OTP-26.0", "OTP-26.2.5.15")], boundaries: boundaries) ==
               %{"versions" => [], "issues" => ["cannot resolve tftp's version for a range"]}
    end

    test "translates each fix transition to the app's own version" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "ssh",
        version_type: :otp,
        tag_suffixes: []
      }

      boundaries = %{introduced: "26.0", fixed: ["26.2.5.15", "27.3.4.3"], open?: true}

      assert %{"versions" => [entry], "issues" => []} =
               Emit.channel(channel, [range("OTP-26.0", "OTP-26.2.5.15")], boundaries: boundaries)

      assert entry["version"] == "5.0"
      assert entry["lessThan"] == "*"

      assert entry["changes"] == [
               %{"at" => "5.1.4.12", "status" => "unaffected"},
               %{"at" => "5.2.3.4", "status" => "unaffected"}
             ]
    end

    test "translates each OTP release bound to the app's own version" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "ssh",
        version_type: :otp,
        tag_suffixes: []
      }

      ranges = [range("OTP-26.0", "OTP-26.2.5.15"), range("OTP-27.0", "OTP-27.3.4.3")]

      assert Emit.channel(channel, ranges, []) == %{
               "versions" => [
                 %{
                   "version" => "5.0",
                   "lessThan" => "5.1.4.12",
                   "status" => "affected",
                   "versionType" => "otp"
                 },
                 %{
                   "version" => "5.2",
                   "lessThan" => "5.2.3.4",
                   "status" => "affected",
                   "versionType" => "otp"
                 }
               ],
               "issues" => []
             }
    end

    test "an unbounded app range stays open" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "ssh",
        version_type: :otp,
        tag_suffixes: []
      }

      assert %{"versions" => [%{"version" => "5.0", "lessThan" => "*"}]} =
               Emit.channel(channel, [range("OTP-26.0", :unbounded)], [])
    end

    # A pkg:otp channel on Elixir's repo versions with Elixir, not with OTP.
    test "a pkg:otp channel versioned as semver stays plain semver" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "elixir",
        version_type: :semver,
        tag_suffixes: []
      }

      assert %{"versions" => [%{"version" => "1.5.0", "versionType" => "semver"}]} =
               Emit.channel(channel, [range("v1.5.0", "v1.20.1")], [])
    end

    test "an otp-versioned channel naming no application keeps the release bounds" do
      channel = %PackageChannel{
        purl_type: "sid",
        namespace: "erlang.org",
        name: "otp",
        version_type: :otp,
        tag_suffixes: []
      }

      assert %{"versions" => [%{"version" => "26.0", "lessThan" => "26.2.5.15"}]} =
               Emit.channel(channel, [range("OTP-26.0", "OTP-26.2.5.15")], [])
    end
  end

  describe "channel/3 git" do
    @intro String.duplicate("a", 40)
    @fix1 String.duplicate("b", 40)
    @fix2 String.duplicate("c", 40)

    defp repo_channel do
      %PackageChannel{purl_type: "github", namespace: "acme", name: "acme", tag_suffixes: []}
    end

    test "single fix renders a bounded git-sha range" do
      opts = [intro_shas: [@intro], fix_shas: [@fix1]]

      assert Emit.channel(repo_channel(), [], opts) == %{
               "versions" => [
                 %{
                   "version" => @intro,
                   "lessThan" => @fix1,
                   "status" => "affected",
                   "versionType" => "git"
                 }
               ],
               "issues" => []
             }
    end

    test "multiple fixes render a changes[] chain (SHAs aren't orderable)" do
      opts = [intro_shas: [@intro], fix_shas: [@fix1, @fix2]]

      assert Emit.channel(repo_channel(), [], opts) == %{
               "versions" => [
                 %{
                   "version" => @intro,
                   "lessThan" => "*",
                   "status" => "affected",
                   "versionType" => "git",
                   "changes" => [
                     %{"at" => @fix1, "status" => "unaffected"},
                     %{"at" => @fix2, "status" => "unaffected"}
                   ]
                 }
               ],
               "issues" => []
             }
    end

    test "no fix leaves the range open" do
      opts = [intro_shas: [@intro], fix_shas: []]

      assert %{"versions" => [%{"version" => @intro, "lessThan" => "*"}]} =
               Emit.channel(repo_channel(), [], opts)
    end

    test "no introducing commit is an issue, not a range" do
      opts = [intro_shas: [], fix_shas: [@fix1]]

      assert %{"versions" => [], "issues" => [issue]} = Emit.channel(repo_channel(), [], opts)
      assert issue =~ "no commit SHA"
    end

    # Release versions belong to the registry channels; the repository entry
    # only ever says which commits are affected.
    test "commit SHAs only, whatever release ranges were derived" do
      opts = [intro_shas: [@intro], fix_shas: [@fix1]]

      assert %{"versions" => versions} =
               Emit.channel(repo_channel(), [range("OTP-26.0", "OTP-27.0")], opts)

      assert Enum.all?(versions, &(&1["versionType"] == "git"))
    end
  end

  describe "cpe_matches/2" do
    test "one non-overlapping match per range, bare bounds" do
      ranges = [range("v1.0.0", "v1.5.3"), range("v1.6.0", "v2.1.0")]

      assert Emit.cpe_matches(ranges) == [
               %{"versionStartIncluding" => "1.0.0", "versionEndExcluding" => "1.5.3"},
               %{"versionStartIncluding" => "1.6.0", "versionEndExcluding" => "2.1.0"}
             ]
    end

    test "an unbounded range has nil upper bound" do
      assert Emit.cpe_matches([range("v1.0.0", :unbounded)]) == [
               %{"versionStartIncluding" => "1.0.0", "versionEndExcluding" => nil}
             ]
    end

    # NVD writes OTP's lowest affected line as a bare {versionEndExcluding: ...}
    # (see CVE-2022-37026); R-series tags are never used as range bounds.
    test "a root-commit intro drops the lowest range's lower bound" do
      ranges = [range("OTP-26.0", "OTP-26.2.5.15"), range("OTP-27.0", "OTP-27.3.4.3")]

      assert Emit.cpe_matches(ranges, otp_root_intro?: true) == [
               %{"versionStartIncluding" => nil, "versionEndExcluding" => "26.2.5.15"},
               %{"versionStartIncluding" => "27.0", "versionEndExcluding" => "27.3.4.3"}
             ]
    end

    test "a non-root intro keeps every lower bound" do
      ranges = [range("OTP-26.0", "OTP-26.2.5.15")]

      assert Emit.cpe_matches(ranges, otp_root_intro?: false) == [
               %{"versionStartIncluding" => "26.0", "versionEndExcluding" => "26.2.5.15"}
             ]
    end
  end

  describe "OTP status-change form" do
    defp otp_channel do
      %PackageChannel{
        purl_type: "sid",
        namespace: "erlang.org",
        name: "otp",
        version_type: :otp,
        tag_suffixes: []
      }
    end

    test "several fixes become one open entry with a transition each" do
      boundaries = %{introduced: "27.0", fixed: ["27.3.4.15", "28.5.0.4"], open?: true}

      assert %{"versions" => [entry]} =
               Emit.channel(otp_channel(), [], boundaries: boundaries)

      assert entry == %{
               "version" => "27.0",
               "lessThan" => "*",
               "status" => "affected",
               "versionType" => "otp",
               "changes" => [
                 %{"at" => "27.3.4.15", "status" => "unaffected"},
                 %{"at" => "28.5.0.4", "status" => "unaffected"}
               ]
             }
    end

    # `lessThan` says the same span. The open form would additionally claim every
    # version above the bound, and a fix on a maintenance branch cannot close a
    # line that does not exist yet.
    test "a single fix stays a bounded range" do
      boundaries = %{introduced: "26.0", fixed: ["26.2.5.15"], open?: true}
      ranges = [range("OTP-26.0", "OTP-26.2.5.15")]

      assert %{"versions" => [entry]} =
               Emit.channel(otp_channel(), ranges, boundaries: boundaries)

      assert entry == %{
               "version" => "26.0",
               "lessThan" => "26.2.5.15",
               "status" => "affected",
               "versionType" => "otp"
             }
    end

    # An open entry claims everything above its lower bound, so it may only be
    # used when the fixes actually account for that.
    test "boundaries that would overclaim stay bounded ranges" do
      boundaries = %{introduced: "27.0", fixed: ["27.3.4.15", "28.5.0.4"], open?: false}
      ranges = [range("OTP-27.0", "OTP-27.3.4.15")]

      assert %{"versions" => [entry]} =
               Emit.channel(otp_channel(), ranges, boundaries: boundaries)

      refute Map.has_key?(entry, "changes")
      assert entry["lessThan"] == "27.3.4.15"
    end
  end

  describe "OTP root-commit sentinel (otp_root_intro?: true)" do
    @root "84adefa331c4159d432d22840663c38f155cd4c1"

    setup do
      Req.Test.stub(OtpVersionsTable, fn conn ->
        Plug.Conn.send_resp(conn, 200, """
        OTP-26.2.5.15 : ssh-5.2.11.9 stdlib-5.2.3.1 :
        OTP-26.0 : ssh-5.0 stdlib-5.0 :
        OTP-17.0 : ssh-3.0.1 stdlib-2.0 :
        """)
      end)

      on_exit(&OtpVersionsTable.reset/0)
    end

    test "otp_root_commit?/1 recognises the root import commit" do
      assert Emit.otp_root_commit?(@root)
      refute Emit.otp_root_commit?(String.duplicate("a", 40))
    end

    # A root-commit intro is contained by every tag, and R tags are not versions,
    # so the first range opens at the oldest numeric release, 17.0.
    test "prepends an unknown range to an OTP app channel, bounded by the app's version at the first affected release" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "stdlib",
        version_type: :otp,
        tag_suffixes: []
      }

      assert %{"versions" => [sentinel, released]} =
               Emit.channel(channel, [range("OTP-17.0", "OTP-26.2.5.15")], otp_root_intro?: true)

      assert sentinel == %{
               "version" => "0",
               "lessThan" => "2.0",
               "status" => "unknown",
               "versionType" => "otp"
             }

      assert released["version"] == "2.0"
    end

    test "prepends an unknown range bounded by the first affected release to the OTP release channel" do
      channel = %PackageChannel{
        purl_type: "sid",
        namespace: "erlang.org",
        name: "otp",
        version_type: :otp,
        tag_suffixes: []
      }

      assert %{"versions" => [sentinel, released]} =
               Emit.channel(channel, [range("OTP-17.0", "OTP-26.2.5.15")], otp_root_intro?: true)

      assert sentinel == %{
               "version" => "0",
               "lessThan" => "17.0",
               "status" => "unknown",
               "versionType" => "otp"
             }

      assert released == %{
               "version" => "17.0",
               "lessThan" => "26.2.5.15",
               "status" => "affected",
               "versionType" => "otp"
             }
    end

    # A fix and re-introduction splits the timeline, so the second range starts
    # well above the sentinel's bound.
    test "the sentinel never overlaps the first affected range" do
      channel = %PackageChannel{
        purl_type: "sid",
        namespace: "erlang.org",
        name: "otp",
        version_type: :otp,
        tag_suffixes: []
      }

      ranges = [range("OTP-17.0", "OTP-18.0"), range("OTP-26.0", "OTP-26.2.5.15")]

      assert %{"versions" => [sentinel | affected]} =
               Emit.channel(channel, ranges, otp_root_intro?: true)

      assert sentinel["lessThan"] == "17.0"
      assert Enum.map(affected, & &1["version"]) == ["17.0", "26.0"]
    end

    # `otp_root_intro?` holds whenever the root commit has no explicit version,
    # including when no release carries the vulnerability at all.
    test "no sentinel when no range places the root commit" do
      channel = %PackageChannel{
        purl_type: "sid",
        namespace: "erlang.org",
        name: "otp",
        version_type: :otp,
        tag_suffixes: []
      }

      assert %{"versions" => versions} = Emit.channel(channel, [], otp_root_intro?: true)

      assert versions == []
    end

    # erlang/otp's history starts at the root commit, so "0 → <root sha>" would
    # claim a span of commits that does not exist.
    test "a git channel carries no sentinel even when the intro is the root commit" do
      channel = %PackageChannel{purl_type: "github", namespace: "erlang", name: "otp"}
      opts = [otp_root_intro?: true, intro_shas: [@root], fix_shas: ["fix"]]

      assert %{"versions" => versions} = Emit.channel(channel, [], opts)

      refute Enum.any?(versions, &(&1["status"] == "unknown"))
    end

    test "no sentinel when the intro is not the root commit" do
      channel = %PackageChannel{
        purl_type: "otp",
        name: "ssh",
        version_type: :otp,
        tag_suffixes: []
      }

      assert %{"versions" => versions} =
               Emit.channel(channel, [range("OTP-26.0", "OTP-26.2.5.15")], otp_root_intro?: false)

      refute Enum.any?(versions, &(&1["status"] == "unknown"))
    end

    # A semver channel never sees the root commit; the flag is OTP-only.
    test "no sentinel on a semver channel" do
      channel = %PackageChannel{purl_type: "hex", name: "acme", tag_suffixes: []}

      assert %{"versions" => versions} =
               Emit.channel(channel, [range("v1.0.0", "v1.5.3")], otp_root_intro?: true)

      refute Enum.any?(versions, &(&1["status"] == "unknown"))
    end
  end
end
