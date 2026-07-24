# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.EmitTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Derivation.Emit
  alias Varsel.Cases.Derivation.OtpVersionsTable
  alias Varsel.Cases.PackageChannel

  defp range(from, until), do: %{from: from, until: until}

  describe "channel/3 semver" do
    test "each range is a separate bounded entry, prefix stripped" do
      channel = %PackageChannel{purl_type: :hex, name: "acme", tag_suffixes: []}
      ranges = [range("v1.7.0", "v1.7.22"), range("v1.8.0", "v1.8.6")]

      assert Emit.channel(channel, ranges, otp_platform?: false) == %{
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
      channel = %PackageChannel{purl_type: :hex, name: "acme", tag_suffixes: []}

      assert %{"versions" => [%{"lessThan" => "*"}]} =
               Emit.channel(channel, [range("v1.0.0", :unbounded)], otp_platform?: false)
    end
  end

  describe "channel/3 oci" do
    test "repeats each range per tag-suffix flavor" do
      channel = %PackageChannel{purl_type: :oci, name: "acme", tag_suffixes: ["elixir", "erlang"]}

      assert Emit.channel(channel, [range("v1.9.0-rc1", "v1.15.4")], otp_platform?: false) == %{
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
  end

  describe "channel/3 otp app translation" do
    setup do
      Req.Test.stub(OtpVersionsTable, fn conn ->
        Plug.Conn.send_resp(conn, 200, """
        OTP-27.3.4.3 : ssh-5.2.3.4 stdlib-6.2.2.1 :
        OTP-27.0 : ssh-5.2 stdlib-6.0 :
        OTP-26.2.5.15 : ssh-5.1.4.12 stdlib-5.2.3.4 :
        OTP-26.0 : ssh-5.0 stdlib-5.0 :
        """)
      end)

      on_exit(&OtpVersionsTable.reset/0)
    end

    test "translates each OTP release bound to the app's own version" do
      channel = %PackageChannel{purl_type: :otp, name: "ssh", tag_suffixes: []}
      ranges = [range("OTP-26.0", "OTP-26.2.5.15"), range("OTP-27.0", "OTP-27.3.4.3")]

      assert Emit.channel(channel, ranges, otp_platform?: true) == %{
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

    test "a pkg:otp channel on a non-otp repo stays plain semver" do
      channel = %PackageChannel{purl_type: :otp, name: "elixir", tag_suffixes: []}

      assert %{"versions" => [%{"version" => "1.5.0", "versionType" => "semver"}]} =
               Emit.channel(channel, [range("v1.5.0", "v1.20.1")], otp_platform?: false)
    end
  end

  describe "git/4" do
    @intro String.duplicate("a", 40)
    @fix1 String.duplicate("b", 40)
    @fix2 String.duplicate("c", 40)

    test "single fix renders a bounded git-sha range" do
      assert Emit.git([@intro], [@fix1], [], otp_platform?: false) == %{
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
      assert Emit.git([@intro], [@fix1, @fix2], [], otp_platform?: false) == %{
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

    test "OTP packages prepend the OTP release block ahead of the git range" do
      ranges = [range("OTP-26.0", "OTP-26.2.5.15")]

      assert %{"versions" => [otp_block, git_block]} =
               Emit.git([@intro], [@fix1], ranges, otp_platform?: true)

      assert otp_block == %{
               "version" => "26.0",
               "lessThan" => "26.2.5.15",
               "status" => "affected",
               "versionType" => "otp"
             }

      assert git_block["versionType"] == "git"
    end
  end

  describe "cpe_matches/1" do
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
  end

  describe "OTP root-commit sentinel (otp_root_intro?: true)" do
    @root "84adefa331c4159d432d22840663c38f155cd4c1"

    setup do
      Req.Test.stub(OtpVersionsTable, fn conn ->
        Plug.Conn.send_resp(conn, 200, """
        OTP-26.2.5.15 : ssh-5.2.11.9 :
        OTP-26.0 : ssh-5.0 :
        """)
      end)

      on_exit(&OtpVersionsTable.reset/0)
    end

    test "otp_root_commit?/1 recognises the root import commit" do
      assert Emit.otp_root_commit?(@root)
      refute Emit.otp_root_commit?(String.duplicate("a", 40))
    end

    test "prepends an unknown pre-R13B03 range to an OTP app channel, bounded by the app's R13B03 version" do
      channel = %PackageChannel{purl_type: :otp, name: "ssh", tag_suffixes: []}
      # ssh shipped 1.1.7 in R13B03 (from priv/otp_pre17_versions.json).
      opts = [otp_platform?: true, otp_root_intro?: true]

      assert %{"versions" => [sentinel | _]} =
               Emit.channel(channel, [range("OTP-26.0", "OTP-26.2.5.15")], opts)

      assert sentinel == %{
               "version" => "0",
               "lessThan" => "1.1.7",
               "status" => "unknown",
               "versionType" => "otp"
             }
    end

    test "prepends an unknown range bounded by R13B03 to the git entry's OTP release block, and by the root commit to the git-SHA block" do
      opts = [otp_platform?: true, otp_root_intro?: true]

      assert %{"versions" => versions} =
               Emit.git([@root], ["fix"], [range("OTP-26.0", "OTP-26.2.5.15")], opts)

      otp_sentinel =
        Enum.find(versions, &(&1["versionType"] == "otp" and &1["status"] == "unknown"))

      git_sentinel =
        Enum.find(versions, &(&1["versionType"] == "git" and &1["status"] == "unknown"))

      assert otp_sentinel["lessThan"] == "R13B03"
      assert git_sentinel["lessThan"] == @root
    end

    test "no sentinel when the intro is not the root commit" do
      channel = %PackageChannel{purl_type: :otp, name: "ssh", tag_suffixes: []}
      opts = [otp_platform?: true, otp_root_intro?: false]

      assert %{"versions" => versions} =
               Emit.channel(channel, [range("OTP-26.0", "OTP-26.2.5.15")], opts)

      refute Enum.any?(versions, &(&1["status"] == "unknown"))
    end
  end
end
