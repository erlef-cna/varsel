# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

{ pkgs, lib, config, inputs, ... }:

let
  cvelintVersion = "0.6.0";

  cvelintAssets = {
    "aarch64-darwin" = {
      asset = "cvelint_Darwin_arm64.tar.gz";
      sha256 = "f5b1ad176543424197de890397d4fb139b56f23b3ca0be0b44cbcaedad579efc";
    };
    "x86_64-darwin" = {
      asset = "cvelint_Darwin_x86_64.tar.gz";
      sha256 = "7fe439fcf4d05f643276edcfc207fc5bded7a587cd4a7765268de4e30a4128e2";
    };
    "aarch64-linux" = {
      asset = "cvelint_Linux_arm64.tar.gz";
      sha256 = "c69d173d04343f8392a1eb8c9b41e4af622bbc83caf08d78de01cd2149ddae48";
    };
    "x86_64-linux" = {
      asset = "cvelint_Linux_x86_64.tar.gz";
      sha256 = "88078c84238ae13053328fc28c4ab9c63482d3b4d4ac3b1366a168be7d3e65cf";
    };
  };

  cvelintAsset =
    cvelintAssets.${pkgs.stdenv.hostPlatform.system}
      or (throw "cvelint: unsupported system ${pkgs.stdenv.hostPlatform.system}");

  cvelint = pkgs.stdenvNoCC.mkDerivation {
    pname = "cvelint";
    version = cvelintVersion;

    src = pkgs.fetchurl {
      url = "https://github.com/mprpic/cvelint/releases/download/v${cvelintVersion}/${cvelintAsset.asset}";
      inherit (cvelintAsset) sha256;
    };

    sourceRoot = ".";

    installPhase = ''
      install -Dm755 cvelint $out/bin/cvelint
    '';
  };

  elixir = pkgs.beam29Packages.elixir_1_20;

  # The mix release is built OUTSIDE Nix (plain `mix release`), then staged at
  # ./container/release so the container can package it. Stage it with:
  #   mix release --overwrite
  #   rm -rf container/release && cp -r _build/prod/rel/varsel container/release
  # (The directory is git-ignored; the container build reads it as a path.)
  #
  # The release's boot scripts embed the BUILD-TIME /nix/store path of the full
  # erlang package (an ERTS ROOTDIR fallback in erts/bin/start plus the elixir/
  # iex shebangs). Left intact, Nix treats that as a runtime reference and drags
  # the ENTIRE erlang closure — compiler, dialyzer, wx, docs, ~gigabytes — into
  # the image, even though the release bundles its own ERTS. Strip it: the
  # $0-relative ROOTDIR lookup that precedes the fallback already resolves to
  # the bundled ERTS, and the bash shebangs become /bin/sh (busybox).
  #
  # The remaining store references (openssl/ncurses/zlib/glibc the ERTS links
  # against) are small, legitimate, and pulled in automatically.
  release = pkgs.runCommandLocal "varsel-release" { } ''
    cp -r --no-preserve=mode,ownership ${./container/release} $out
    chmod -R u+w "$out"

    grep -rlZ '/nix/store/[a-z0-9]\{32\}-erlang-\|#!/nix/store/[^/]*/bin/sh' "$out" \
      | while IFS= read -r -d "" f; do
      sed -i \
        -e 's,#!/nix/store/[^/]*/bin/sh,#!/bin/sh,g' \
        -e 's,/nix/store/[a-z0-9]\{32\}-erlang-[^/]*/lib/erlang,${placeholder "out"}/lib/erlang,g' \
        "$f"
    done

    # Guard against the big regression specifically: no erlang-package refs.
    if grep -rq '/nix/store/[a-z0-9]\{32\}-erlang-' "$out"; then
      echo "error: release still references the full erlang package:" >&2
      grep -rl '/nix/store/[a-z0-9]\{32\}-erlang-' "$out" >&2
      exit 1
    fi
  '';

  # busybox supplies the POSIX utilities (sh, readlink, dirname, cut, sed, awk…)
  # the release boot scripts call, in one small static binary. The ERTS runtime
  # libraries come in via the release's own references, so they are not repeated
  # here. cvelint is added separately (static Go binary).
  releaseLibs = pkgs.buildEnv {
    name = "varsel-release-libs";
    paths = [ pkgs.busybox ];
  };
in
{
  packages = with pkgs; [
    git
    cvelint
  ];

  languages.elixir = {
    enable = true;
    package = elixir;
  };

  # Production OCI image: packages the prebuilt mix release, the runtime
  # libraries its ERTS binaries need, and cvelint (used at runtime to validate
  # CVE records). The release itself is built with plain `mix release` (see the
  # release CI workflow), not by Nix.
  #
  # Stage:  mix release --overwrite && cp -r _build/prod/rel/varsel container/release
  # Build:  devenv container build prod
  # Push:   devenv container copy prod                (tag via -O …version)
  containers.prod = {
    name = "varsel";
    registry = "docker://ghcr.io/erlef-cna/";
    version = "edge";
    copyToRoot = [ release releaseLibs cvelint ];
    startupCommand = "/bin/server";
  };

  languages.javascript = {
    enable = true;
    npm = {
      enable = true;
      install.enable = true;
    };
    directory = "./assets";
  };

  dotenv.enable = true;

  services.postgres = {
    enable = true;
    listen_addresses = "*";

    initialDatabases = [
      { name = "varsel_dev";  user = "postgres"; pass = "postgres"; }
      { name = "varsel_test"; user = "postgres"; pass = "postgres"; }
      { name = "varsel_prod"; user = "postgres"; pass = "postgres"; }
    ];

    initialScript = ''
      ALTER ROLE postgres WITH CREATEDB SUPERUSER;
    '';
  };

  claude.code = {
    enable = true;
    commands = {
      mix-format = ''
      Format all Elixir files in the project using mix format.

      ```bash
      mix format
      ```
      '';
    };

    hooks = {
      mix-format = {
        enable = true;
        name = "Format Elixir code with mix format";
        hookType = "PostToolUse";
        matcher = "^(Edit|MultiEdit|Write)$";
        command = "mix format";
      };
    };
  };

  git-hooks.hooks = {
    shellcheck.enable = true;
    credo.enable = true;
    detect-private-keys.enable = true;
    dialyzer.enable = true;
    mix-format.enable = true;
    reuse.enable = true;
    zizmor.enable = true;
  };
}
