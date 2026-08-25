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

    test ":otp routes to OTP semantics" do
      assert VC.compare(:otp, "OTP-26.2.5", "OTP-27.0") == :lt
      assert VC.release?(:otp, "OTP-17.0")
      refute VC.release?(:otp, "OTP_R13B03")
      refute VC.release?(:otp, "OTP_R16B03_yielding_binary_to_term")
      assert {:ok, _} = VC.parse(:otp, "OTP-27.3.4.3")
      assert VC.prerelease?(:otp, "29.0-rc1")
    end
  end

  describe "the zero bound" do
    test "orders below every version, in either scheme" do
      for kind <- [:semver, :otp] do
        assert VC.release?(kind, "0")
        refute VC.prerelease?(kind, "0")
        assert VC.compare(kind, "0", "0") == :eq
      end

      assert VC.compare(:otp, "0", "17.0") == :lt
      assert VC.compare(:otp, "27.0", "0") == :gt
      assert VC.compare(:semver, "0", "0.0.1") == :lt
      assert VC.compare(:semver, "1.0.0", "0") == :gt
    end

    # It is a bound, not a version: no scheme parses it.
    test "does not parse under either scheme" do
      assert VC.parse(:otp, "0") == :error
      assert VC.parse(:semver, "0") == :error
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

    test "sorts numeric releases ascending under :otp" do
      items = [%{v: "OTP-27.0"}, %{v: "OTP-17.0"}, %{v: "OTP-26.2.5"}]

      assert VC.sort(:otp, items, & &1.v) == [
               %{v: "OTP-17.0"},
               %{v: "OTP-26.2.5"},
               %{v: "OTP-27.0"}
             ]
    end
  end
end
