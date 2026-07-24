# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.VersionComparatorTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Reachability.VersionComparator, as: VC

  # The scheme-specific behaviour is exercised in OTPVersionTest / SemverVersionTest.
  # Here we only confirm the dispatcher routes each kind to the right module.

  describe "dispatch" do
    test ":semver routes to strict semver semantics" do
      assert VC.compare(:semver, "1.2.3", "1.10.0") == :lt
      assert VC.release?(:semver, "v1.2.3")
      refute VC.release?(:semver, "nightly")
      assert {:ok, _} = VC.parse(:semver, "1.7.22")
      assert VC.parse(:semver, "nightly") == :error
    end

    test ":otp routes to OTP semantics incl. R-series" do
      assert VC.compare(:otp, "OTP_R16B03-1", "OTP-17.0") == :lt
      assert VC.release?(:otp, "OTP_R13B03")
      refute VC.release?(:otp, "OTP_R16B03_yielding_binary_to_term")
      assert {:ok, _} = VC.parse(:otp, "OTP_R14A")
      assert VC.prerelease?(:otp, "OTP_R16B01_RC1")
    end
  end

  describe "sort/3" do
    test "sorts items ascending by their version under kind" do
      items = [%{v: "1.10.0"}, %{v: "1.2.0"}, %{v: "1.2.0-rc1"}]

      assert VC.sort(:semver, items, & &1.v) == [
               %{v: "1.2.0-rc1"},
               %{v: "1.2.0"},
               %{v: "1.10.0"}
             ]
    end

    test "R-series sorts below modern under :otp" do
      items = [%{v: "OTP-17.0"}, %{v: "OTP_R16B03-1"}, %{v: "OTP_R13B03"}]

      assert VC.sort(:otp, items, & &1.v) == [
               %{v: "OTP_R13B03"},
               %{v: "OTP_R16B03-1"},
               %{v: "OTP-17.0"}
             ]
    end
  end
end
