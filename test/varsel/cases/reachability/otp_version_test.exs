# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.OTPVersionTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Reachability.OTPVersion

  describe "parse/1" do
    test "strips OTP-/OTP_ prefixes and keeps the raw name" do
      assert {:ok, %OTPVersion{era: 1, raw: "OTP-27.3.4.3"}} = OTPVersion.parse("OTP-27.3.4.3")
      assert {:ok, %OTPVersion{era: 0, raw: "OTP_R13B03"}} = OTPVersion.parse("OTP_R13B03")
      assert {:ok, %OTPVersion{era: 1, raw: "27.0"}} = OTPVersion.parse("27.0")
    end

    test "rejects topic/feature tags" do
      assert OTPVersion.parse("OTP_R16B03_yielding_binary_to_term") == :error
      assert OTPVersion.parse("R16B02_yielding_binary_to_term") == :error
    end

    test "flags pre-releases" do
      assert {:ok, %OTPVersion{prerelease?: true}} = OTPVersion.parse("29.0-rc1")
      assert {:ok, %OTPVersion{prerelease?: true}} = OTPVersion.parse("OTP_R16B01_RC1")

      assert {:ok, %OTPVersion{prerelease?: true}} =
               OTPVersion.parse("OTP_R16A_RELEASE_CANDIDATE")

      assert {:ok, %OTPVersion{prerelease?: false}} = OTPVersion.parse("OTP_R16B03-1")
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
      assert OTPVersion.compare("OTP_R16B01_RC1", "OTP_R16B01") == :lt
    end

    test "every R release orders below every modern release, and among themselves" do
      tags = ~w(OTP-17.0 OTP_R16B03-1 OTP_R13B03 OTP_R15B03-1 OTP_R14A OTP-27.0)

      assert Enum.sort_by(tags, & &1, &(OTPVersion.compare(&1, &2) != :gt)) ==
               ~w(OTP_R13B03 OTP_R14A OTP_R15B03-1 OTP_R16B03-1 OTP-17.0 OTP-27.0)
    end
  end

  describe "release?/1 and prerelease?/1" do
    test "release? accepts modern + R-series, rejects topic tags" do
      assert OTPVersion.release?("OTP-27.3.4.3")
      assert OTPVersion.release?("OTP_R13B03")
      refute OTPVersion.release?("OTP_R16B03_yielding_binary_to_term")
    end

    test "prerelease? detects rc and RC markers" do
      assert OTPVersion.prerelease?("29.0-rc3")
      assert OTPVersion.prerelease?("OTP_R16B01_RC1")
      refute OTPVersion.prerelease?("29.0")
    end
  end
end
