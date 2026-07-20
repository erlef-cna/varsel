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
in
{
  packages = with pkgs; [
    git
    jq
    cvelint
  ];

  languages.elixir = {
    enable = true;
    package = pkgs.beam29Packages.elixir_1_20;
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

  # Minimal production image, built from the SAME locked nixpkgs/cvelint as this
  # shell. Independent of the dev environment (no postgres/languages/hooks are
  # pulled in). Stage the release first, then build:
  #   mix release --overwrite && cp -r _build/prod/rel/varsel container/release
  #   devenv build outputs.container
  outputs.container = import ./nix/container.nix {
    inherit pkgs cvelint;
    nix2container = inputs.nix2container.packages.${pkgs.stdenv.hostPlatform.system}.nix2container;
  };
}
