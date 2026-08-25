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

    test "flags pre-releases" do
      assert {:ok, %OTPVersion{prerelease?: true}} = OTPVersion.parse("29.0-rc1")
      assert {:ok, %OTPVersion{prerelease?: false}} = OTPVersion.parse("29.0")
    end
  end

  describe "compare/2" do
    test "orders modern versions numerically" do
      assert OTPVersion.compare("27.3.4.3", "27.3.4.10") == :lt
      assert OTPVersion.compare("28.0.3", "27.3.4.3") == :gt
      assert OTPVersion.compare("OTP-27.0", "27.0") == :eq
    end

    test "a pre-release orders below its release" do
      assert OTPVersion.compare("29.0-rc1", "29.0") == :lt
    end

    test "the floor orders below every release" do
      assert OTPVersion.compare(OTPVersion.floor(), "17.0") == :lt
      assert OTPVersion.compare(OTPVersion.floor(), "29.0-rc1") == :lt
    end

    test "sorts an ascending timeline" do
      tags = ~w(OTP-27.0 OTP-17.0 0 OTP-26.2.5 29.0-rc1 29.0)

      assert Enum.sort_by(tags, & &1, &(OTPVersion.compare(&1, &2) != :gt)) ==
               ~w(0 OTP-17.0 OTP-26.2.5 OTP-27.0 29.0-rc1 29.0)
    end

    # Neither bounds a range, so the only requirement is that they never displace
    # one that does.
    test "a non-release sorts above every release" do
      assert OTPVersion.compare("nightly", "29.0") == :gt
      assert OTPVersion.compare("OTP_R13B03", "17.0") == :gt
    end
  end

  describe "release?/1 and prerelease?/1" do
    test "release? accepts numeric releases, rejects R-series and topic tags" do
      assert OTPVersion.release?("OTP-27.3.4.3")
      refute OTPVersion.release?("OTP_R13B03")
      refute OTPVersion.release?("OTP_R16B03_yielding_binary_to_term")
    end

    test "prerelease? detects rc markers" do
      assert OTPVersion.prerelease?("29.0-rc3")
      refute OTPVersion.prerelease?("29.0")
      refute OTPVersion.prerelease?("OTP_R16B01_RC1")
    end
  end
end
