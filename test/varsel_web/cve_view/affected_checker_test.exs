# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveView.AffectedCheckerTest do
  use ExUnit.Case, async: true

  alias VarselWeb.CveView
  alias VarselWeb.CveView.AffectedChecker, as: Checker

  describe "parse/2 — semver" do
    test "parses a plain major.minor.patch version" do
      assert %Version{major: 1, minor: 4, patch: 9} = Checker.parse("1.4.9", "semver")
    end

    test "zero-pads short major or major.minor versions" do
      assert Checker.parse("1.4", "semver") == Checker.parse("1.4.0", "semver")
      assert Checker.parse("2", "semver") == Checker.parse("2.0.0", "semver")
    end

    test "parses pre-release suffixes" do
      assert %Version{pre: ["rc1"]} = Checker.parse("1.4.9-rc1", "semver")
    end

    test "trims surrounding whitespace" do
      assert Checker.parse("  1.4.9  ", "semver") == Checker.parse("1.4.9", "semver")
    end

    test "rejects garbage input" do
      assert Checker.parse("", "semver") == :error
      assert Checker.parse("bandit-1.4", "semver") == :error
      assert Checker.parse("latest", "semver") == :error
      assert Checker.parse("1.4.x", "semver") == :error
    end
  end

  describe "parse/2 — otp" do
    test "parses dot-separated numeric segments" do
      assert Checker.parse("26.2.5.6", "otp") == {26, 2, 5, 6}
    end

    test "strips an OTP- prefix, with or without it present" do
      assert Checker.parse("OTP-26.2.5.6", "otp") == Checker.parse("26.2.5.6", "otp")
    end

    test "zero-pads missing trailing segments" do
      assert Checker.parse("26.2", "otp") == {26, 2, 0, 0}
      assert Checker.parse("26", "otp") == {26, 0, 0, 0}
    end

    test "rejects garbage input" do
      assert Checker.parse("", "otp") == :error
      assert Checker.parse("bandit-1.4", "otp") == :error
      assert Checker.parse("latest", "otp") == :error
      assert Checker.parse("OTP-26.x", "otp") == :error
    end
  end

  describe "parse/2 — unsupported versionType" do
    test "any type outside semver/otp is unparseable, never matched" do
      assert Checker.parse("2f81c44b1c2d3e4f5061728394a5b6c7d8e9f0a1", "git") == :error
      assert Checker.parse("2026-01-01", "date") == :error
    end
  end

  describe "compare/2" do
    test "compares two semver versions" do
      a = Checker.parse("1.4.9", "semver")
      b = Checker.parse("1.5.0", "semver")
      assert Checker.compare(a, b) == :lt
      assert Checker.compare(b, a) == :gt
      assert Checker.compare(a, a) == :eq
    end

    test "compares two OTP tuples" do
      a = Checker.parse("26.2.5.2", "otp")
      b = Checker.parse("26.2.5.6", "otp")
      assert Checker.compare(a, b) == :lt
      assert Checker.compare(b, a) == :gt
      assert Checker.compare(a, a) == :eq
    end
  end

  describe "supported_type?/1" do
    test "semver and otp are supported" do
      assert Checker.supported_type?("semver")
      assert Checker.supported_type?("otp")
    end

    test "everything else is unsupported" do
      refute Checker.supported_type?("git")
      refute Checker.supported_type?("date")
      refute Checker.supported_type?("custom")
      refute Checker.supported_type?(nil)
    end
  end
end
