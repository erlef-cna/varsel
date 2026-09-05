# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.OTPVersionTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Reachability.OTPVersion

  describe "parse/1" do
    test "strips OTP-/OTP_ prefixes and keeps the raw name" do
      assert {:ok, %OTPVersion{segments: [27, 3, 4, 3], raw: "OTP-27.3.4.3"}} =
               OTPVersion.parse("OTP-27.3.4.3")

      assert {:ok, %OTPVersion{segments: [27, 0], raw: "27.0"}} = OTPVersion.parse("27.0")
    end

    # The version scheme omits less significant parts only when they are 0, so
    # every real release carries at least `<Major>.<Minor>`, and none carries a
    # suffix. https://www.erlang.org/doc/system/versions.html
    test "rejects anything the version scheme does not describe" do
      assert OTPVersion.parse("29") == :error
      assert OTPVersion.parse("0") == :error
      assert OTPVersion.parse("29.0.") == :error
      assert OTPVersion.parse("29.0-latest") == :error
      assert OTPVersion.parse("29.0-rc") == :error
      assert OTPVersion.parse("nightly") == :error
    end

    # Release candidates do not adhere to the version scheme.
    # https://www.erlang.org/doc/system/versions.html
    test "rejects release candidates" do
      assert OTPVersion.parse("29.0-rc1") == :error
      assert OTPVersion.parse("OTP-29.0-rc0") == :error
      assert OTPVersion.parse("27.3.4-rc2") == :error
    end

    # `numeric_segments/1` used to drop the parts it could not read, so a semver
    # tag in an OTP repo parsed as 2.3 and a date as the year.
    test "rejects a tag from another scheme rather than reading its digits" do
      assert OTPVersion.parse("v1.2.3") == :error
      assert OTPVersion.parse("2024-01-01") == :error
    end

    test "accepts the branch versions the scheme allows" do
      assert {:ok, %OTPVersion{segments: [1, 2, 3, 4, 5]}} = OTPVersion.parse("1.2.3.4.5")
    end

    test "rejects topic/feature tags" do
      assert OTPVersion.parse("OTP_R16B03_yielding_binary_to_term") == :error
      assert OTPVersion.parse("R16B02_yielding_binary_to_term") == :error
    end

    # The R series is out of scope: the digits in `R13B03` would otherwise reach
    # the numeric parser and order the tag among the numeric releases.
    test "rejects R-series releases" do
      assert OTPVersion.parse("OTP_R13B03") == :error
      assert OTPVersion.parse("R13B03") == :error
      assert OTPVersion.parse("OTP_R16B03-1") == :error
      assert OTPVersion.parse("R10B-1a") == :error
      assert OTPVersion.parse("OTP_R16B01_RC1") == :error
      assert OTPVersion.parse("OTP_R16A_RELEASE_CANDIDATE") == :error
    end
  end

  describe "compare/2" do
    test "orders versions numerically" do
      assert OTPVersion.compare("27.3.4.3", "27.3.4.10") == :lt
      assert OTPVersion.compare("28.0.3", "27.3.5") == :gt
      assert OTPVersion.compare("OTP-27.0", "27.0") == :eq
    end

    # "Versions of the form 6.0.2.<X> can be compared with normal versions
    # smaller than or equal to 6.0.2, and other versions on the form 6.0.2.<X>."
    # https://www.erlang.org/doc/system/versions.html
    test "a branch version orders against its base and below" do
      assert OTPVersion.compare("27.3.4", "27.3.4.15") == :lt
      assert OTPVersion.compare("27.0", "27.3.4.15") == :lt
      assert OTPVersion.compare("27.3.4.15", "27.3.4.16") == :lt
      assert OTPVersion.compare("28.0", "28.5.0.4") == :lt
    end

    test "a branch version has no order against anything above its base" do
      assert OTPVersion.compare("27.3.4.15", "27.3.5") == :nc
      assert OTPVersion.compare("27.3.4.15", "28.0") == :nc
      assert OTPVersion.compare("28.0", "27.3.4.15") == :nc
      assert OTPVersion.compare("27.0.3.4", "27.0.4") == :nc
    end

    # Branching is recursive: `18.2.4.0.1` branches from `18.2.4.0`, not from
    # `18.2.4`, so it is no sibling of `18.2.4.1`. Verified against erlang/otp's
    # own ancestry — these are its only three five-part tags.
    test "a branch of a branch orders against its own base, not the three-part one" do
      assert OTPVersion.compare("18.2.4", "18.2.4.0.1") == :lt
      assert OTPVersion.compare("18.2.4.0.1", "18.2.4.1") == :nc

      assert OTPVersion.compare("18.3.4", "18.3.4.1.1") == :lt
      assert OTPVersion.compare("18.3.4.1", "18.3.4.1.1") == :lt
      assert OTPVersion.compare("18.3.4.1.1", "18.3.4.2") == :nc

      assert OTPVersion.compare("22.3.4.12", "22.3.4.12.1") == :lt
      assert OTPVersion.compare("22.3.4.12.1", "22.3.4.13") == :nc
    end

    # A branch descends from every earlier patch on the line it hangs off, not
    # just from its immediate base, so it outranks all of them. Confirmed against
    # erlang/otp's commit graph:
    #   git merge-base --is-ancestor OTP-22.3.4.11 OTP-22.3.4.12.1
    test "a branch orders above the earlier patches of the line it hangs off" do
      assert OTPVersion.compare("22.3.4.1", "22.3.4.12.1") == :lt
      assert OTPVersion.compare("22.3.4.11", "22.3.4.12.1") == :lt
      assert OTPVersion.compare("22.3.4.12.1", "22.3.4.11") == :gt
    end

    # The scheme omits a trailing zero past the first two components, so `27.3.0`
    # is spelled `27.3` and is not a version. `:varsel_versions` decides this.
    test "rejects trailing zeros the scheme does not write" do
      refute OTPVersion.release?("27.3.0")
      refute OTPVersion.release?("27.3.4.0")
      refute OTPVersion.release?("27.3.4.1.0")

      assert OTPVersion.release?("27.0")
      assert OTPVersion.release?("27.3.0.1")
    end

    # https://www.erlang.org/doc/system/versions.html
    test "the version scheme's own branching examples" do
      assert OTPVersion.compare("6.0.2", "6.0.2.1") == :lt
      assert OTPVersion.compare("6.0.2.1", "6.0.2.2") == :lt
      assert OTPVersion.compare("6.0.1", "6.0.2.1") == :lt
      assert OTPVersion.compare("6.0.2.1", "6.0.3") == :nc

      # A second branch from the same base inserts a 0 rather than reusing 1.
      assert OTPVersion.compare("6.0.2", "6.0.2.0.1") == :lt
      assert OTPVersion.compare("6.0.2.0.1", "6.0.2.1") == :nc
    end

    test "branches off different bases never meet" do
      assert OTPVersion.compare("27.3.4.15", "28.5.0.4") == :nc
      assert OTPVersion.compare("22.3.4.12.1", "18.3.4.1.1") == :nc
    end

    test "comparable?/2 answers the same question as compare/2" do
      assert OTPVersion.comparable?("27.3.4", "27.3.4.15")
      refute OTPVersion.comparable?("27.3.4.15", "28.0")
    end

    # `sort/3` and range-cutting need one line through the whole set, so this
    # stays total where `compare/2` declines.
    test "total_compare/2 orders what compare/2 will not" do
      assert OTPVersion.total_compare("27.3.4.15", "28.0") == :lt
      assert OTPVersion.total_compare("28.0", "27.3.4.15") == :gt
    end

    test "sorts an ascending timeline" do
      tags = ~w(OTP-27.0 OTP-17.0 OTP-26.2.5 28.3.1 29.0)

      assert Enum.sort_by(tags, & &1, &(OTPVersion.compare(&1, &2) != :gt)) ==
               ~w(OTP-17.0 OTP-26.2.5 OTP-27.0 28.3.1 29.0)
    end
  end

  describe "release?/1 and prerelease?/1" do
    test "release? accepts numeric releases, rejects R-series and topic tags" do
      assert OTPVersion.release?("OTP-27.3.4.3")
      refute OTPVersion.release?("OTP_R13B03")
      refute OTPVersion.release?("OTP_R16B03_yielding_binary_to_term")
    end

    test "release? rejects release candidates" do
      refute OTPVersion.release?("29.0-rc3")
      refute OTPVersion.release?("OTP_R16B01_RC1")
    end

    test "prerelease? is false for every tag" do
      refute OTPVersion.prerelease?("29.0-rc3")
      refute OTPVersion.prerelease?("29.0")
    end
  end
end
