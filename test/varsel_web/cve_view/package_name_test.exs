# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveView.PackageNameTest do
  use ExUnit.Case, async: true

  alias VarselWeb.CveView

  defp name(purl) do
    case CveView.package_name(purl) do
      %{ecosystem: nil, name: name} -> name
      %{ecosystem: ecosystem, name: name} -> "#{ecosystem} / #{name}"
    end
  end

  describe "hex" do
    test "shows the package name" do
      assert name("pkg:hex/plug") == "Hex / plug"
    end

    # A namespace or a repository_url means some other registry, and "Hex /"
    # would then name the wrong one.
    test "a namespaced or self-hosted package is not shortened" do
      namespaced = "pkg:hex/acme/private_thing"
      self_hosted = "pkg:hex/thing?repository_url=https://hex.acme.internal"

      assert name(namespaced) == namespaced
      assert name(self_hosted) == self_hosted
    end
  end

  describe "otp — the repository names the ecosystem" do
    test "an application from erlang/otp is Erlang's" do
      purl = "pkg:otp/ssh?repository_url=https://github.com/erlang/otp"

      assert name(purl) == "Erlang / ssh"
    end

    test "elixir itself is the language, not an application within it" do
      purl = "pkg:otp/elixir?repository_url=https://github.com/elixir-lang/elixir"

      assert name(purl) == "Elixir"
    end

    test "an application shipped with elixir is Elixir's" do
      purl = "pkg:otp/mix?repository_url=https://github.com/elixir-lang/elixir"

      assert name(purl) == "Elixir / mix"
    end

    test "rebar3 stands on its own" do
      purl = "pkg:otp/rebar3?repository_url=https://github.com/erlang/rebar3.git"

      assert name(purl) == "rebar3"
    end

    # `hex` here is the Mix task, not the registry, and `nerves_hub` is the
    # device service — both names say too little on their own.
    test "an application whose own name says too little is spelled out" do
      hex = "pkg:otp/hex?repository_url=https://github.com/hexpm/hex.git"
      nerves = "pkg:otp/nerves_hub?repository_url=https://github.com/nerves-hub/nerves_hub_web"

      assert name(hex) == "Hex Mix Integration"
      assert name(nerves) == "Nerves Hub"
    end

    test "an application from an unrecognised repository is not shortened" do
      purl = "pkg:otp/thing?repository_url=https://github.com/acme/thing"

      assert name(purl) == purl
    end

    # The corpus spells the same repository both ways; one package must not
    # render two different ways depending on which record it came from.
    test "a trailing .git or / does not change the answer" do
      bare = "pkg:otp/ssh?repository_url=https://github.com/erlang/otp"
      dot_git = "pkg:otp/ssh?repository_url=https://github.com/erlang/otp.git"
      trailing = "pkg:otp/ssh?repository_url=https://github.com/erlang/otp/"

      assert name(bare) == "Erlang / ssh"
      assert name(dot_git) == "Erlang / ssh"
      assert name(trailing) == "Erlang / ssh"
    end
  end

  describe "github" do
    # esaml has four forks in the corpus; the repo name alone would make them
    # indistinguishable.
    test "keeps the owner, which is what tells forks apart" do
      assert name("pkg:github/handnot2/esaml") == "GitHub / handnot2/esaml"
      assert name("pkg:github/dropbox/esaml") == "GitHub / dropbox/esaml"
    end
  end

  describe "oci — the registry is part of the address" do
    test "the host names the ecosystem and its path joins the image" do
      purl = "pkg:oci/gleam?repository_url=ghcr.io/gleam-lang"

      assert name(purl) == "ghcr.io / gleam-lang/gleam"
    end

    # An image name alone locates nothing — any registry could host a `redis`.
    test "an image with no registry is not shortened" do
      assert name("pkg:oci/redis") == "pkg:oci/redis"
    end
  end

  describe "sid — a software id names a project, not a package within one" do
    test "the whitelisted ids read as their project" do
      assert name("pkg:sid/erlang.org/otp") == "Erlang"
      assert name("pkg:sid/gleam.run/gleam") == "Gleam"
    end

    test "any other software id is not shortened" do
      purl = "pkg:sid/example.com/thing"

      assert name(purl) == purl
    end
  end

  describe "npm" do
    test "shows the package name" do
      assert name("pkg:npm/phoenix") == "npm / phoenix"
    end

    # A scoped package's identity includes its scope.
    test "a scoped package is not shortened" do
      purl = "pkg:npm/%40acme/thing"

      assert name(purl) == purl
    end
  end

  describe "anything unrecognised prints verbatim" do
    test "an unknown type" do
      assert name("pkg:cargo/serde") == "pkg:cargo/serde"
    end
  end
end
