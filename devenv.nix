# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

{ pkgs, lib, config, inputs, ... }:

let
  # Shared with the production container (see flake.nix / nix/container.nix)
  # so shell and image always run the same cvelint.
  cvelint = pkgs.callPackage ./nix/cvelint.nix { };
in
{
  packages = with pkgs; [
    cvelint
  ];

  languages.elixir = {
    enable = true;
    package = pkgs.beam29Packages.elixir_1_20;
  };

  # Hex/Rebar for mix, installed once per $HOME on shell entry (dev machines
  # and every CI `nix develop` alike). --force only suppresses the prompt;
  # --if-missing makes re-entries a no-op.
  enterShell = ''
    mix local.hex --force --if-missing
    mix local.rebar --force --if-missing
  '';

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
