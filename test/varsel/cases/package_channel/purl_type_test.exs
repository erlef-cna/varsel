# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.PurlTypeTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.PackageChannel.PurlType

  describe "for_repository/1" do
    test "a forge with a registered purl type keeps it" do
      assert PurlType.for_repository("https://github.com/erlang/otp") ==
               {"github", "erlang", "otp", %{}}

      assert PurlType.for_repository("https://bitbucket.org/owner/repo") ==
               {"bitbucket", "owner", "repo", %{}}
    end

    test "the .git suffix and trailing slash do not change the identity" do
      assert PurlType.for_repository("https://github.com/erlang/otp.git") ==
               {"github", "erlang", "otp", %{}}
    end

    # gitlab has no registered purl type, which is exactly why this is not a
    # hand-maintained host table: `purl` decides, and we fall back.
    test "a forge without a purl type becomes generic, carrying vcs_url" do
      assert {"generic", nil, "acme_lib", qualifiers} =
               PurlType.for_repository("https://gitlab.com/group/sub/acme_lib")

      assert qualifiers == %{"vcs_url" => "git+https://gitlab.com/group/sub/acme_lib"}
    end

    test "a self-hosted forge is generic too" do
      assert {"generic", nil, "thing", _qualifiers} =
               PurlType.for_repository("https://git.example.com/team/thing")
    end

    test "no version is pinned — a channel names no single version" do
      {_type, _namespace, name, _qualifiers} =
        PurlType.for_repository("https://github.com/erlang/otp")

      refute name =~ "@"
    end
  end

  describe "default_version_type/1" do
    test "the types we know" do
      assert PurlType.default_version_type("hex") == :semver
      assert PurlType.default_version_type("otp") == :otp
      assert PurlType.default_version_type("oci") == :other
      assert PurlType.default_version_type("github") == :git
      assert PurlType.default_version_type("generic") == :git
    end

    test "anything else versions in semver" do
      assert PurlType.default_version_type("sid") == :semver
      assert PurlType.default_version_type("brand-new-ecosystem") == :semver
      assert PurlType.default_version_type(nil) == :semver
    end
  end

  describe "collection_url/1" do
    test "known registries" do
      assert PurlType.collection_url("hex") == "https://repo.hex.pm"
      assert PurlType.collection_url("npm") == "https://registry.npmjs.org"
    end

    test "types with no single canonical registry have none" do
      assert PurlType.collection_url("oci") == nil
      assert PurlType.collection_url("sid") == nil
      assert PurlType.collection_url(nil) == nil
    end
  end

  describe "cast/1" do
    test "normalizes case and whitespace" do
      assert PurlType.cast("  Hex ") == {:ok, "hex"}
      assert PurlType.cast(:npm) == {:ok, "npm"}
    end

    test "rejects what the purl spec cannot express as a type" do
      assert PurlType.cast("pkg:hex") == :error
      assert PurlType.cast("hex/thing") == :error
      assert PurlType.cast("") == :error
      assert PurlType.cast(nil) == :error
    end
  end

  describe "as an Ash type" do
    test "casting normalizes on the way in" do
      assert Ash.Type.cast_input(PurlType, "  Hex ", []) == {:ok, "hex"}
      assert Ash.Type.cast_input(PurlType, :npm, []) == {:ok, "npm"}
      assert Ash.Type.cast_input(PurlType, nil, []) == {:ok, nil}
    end

    test "casting rejects a malformed type" do
      assert {:error, _} = Ash.Type.cast_input(PurlType, "pkg:hex", [])
      assert {:error, _} = Ash.Type.cast_input(PurlType, 42, [])
    end

    # Storage stays :string so an existing column adopts the type unmigrated.
    test "stores as a plain string" do
      assert Ash.Type.storage_type(PurlType, []) == :string
      assert Ash.Type.dump_to_native(PurlType, "hex", []) == {:ok, "hex"}
      assert Ash.Type.cast_stored(PurlType, "hex", []) == {:ok, "hex"}
    end
  end
end
