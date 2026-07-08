# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

{ pkgs, lib, config, inputs, ... }:

let
  cvelint = pkgs.stdenvNoCC.mkDerivation {
    pname = "cvelint";
    version = "0.4.0";

    src = pkgs.fetchurl {
      url = "https://github.com/mprpic/cvelint/releases/download/v0.4.0/cvelint_Darwin_arm64.tar.gz";
      sha256 = "sha256-F4IFQ9SVZN9IuRgacitWYeKw7MaavBJ1vbPWzdg20dk=";
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
    cvelint
  ];

  languages.elixir = {
    enable = true;
    package = pkgs.beam29Packages.elixir_1_20;
  };

  dotenv.enable = true;

  services.postgres = {
    enable = true;
    listen_addresses = "*";

    initialDatabases = [
      { name = "cve_management_dev";  user = "postgres"; pass = "postgres"; }
      { name = "cve_management_test"; user = "postgres"; pass = "postgres"; }
      { name = "cve_management_prod"; user = "postgres"; pass = "postgres"; }
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
    markdownlint.enable = true;
    mdformat.enable = true;
    mix-format.enable = true;
    reuse.enable = true;
    zizmor.enable = true;
  };
}
