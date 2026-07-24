# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.SemverVersionTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Reachability.SemverVersion

  describe "parse/1" do
    test "strips a leading v and keeps the raw name" do
      assert {:ok, %SemverVersion{version: %Version{major: 1, minor: 7, patch: 22}, raw: "v1.7.22"}} =
               SemverVersion.parse("v1.7.22")

      assert {:ok, %SemverVersion{raw: "2.0.0-rc1"}} = SemverVersion.parse("2.0.0-rc1")
    end

    test "rejects non-version tags" do
      assert SemverVersion.parse("nightly") == :error
      assert SemverVersion.parse("v1.19-latest") == :error
      # strict semver requires MAJOR.MINOR.PATCH
      assert SemverVersion.parse("1.7") == :error
    end
  end

  describe "compare/2" do
    test "orders by semver precedence" do
      assert SemverVersion.compare("1.2.3", "1.10.0") == :lt
      assert SemverVersion.compare("2.0.0", "1.99.99") == :gt
      assert SemverVersion.compare("v1.7.0", "1.7.0") == :eq
    end

    test "a pre-release orders below its release" do
      assert SemverVersion.compare("1.0.0-rc1", "1.0.0") == :lt
      assert SemverVersion.compare("2.0.0-beta.1", "2.0.0-beta.2") == :lt
    end
  end

  describe "release?/1 and prerelease?/1" do
    test "release? follows strict semver" do
      assert SemverVersion.release?("v1.2.3")
      refute SemverVersion.release?("nightly")
    end

    test "prerelease? detects a suffix" do
      assert SemverVersion.prerelease?("1.0.0-rc1")
      refute SemverVersion.prerelease?("1.0.0")
    end
  end
end
