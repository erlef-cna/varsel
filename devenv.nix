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
    flyctl
    skopeo
  ];

  # The elixir package comes from flake.nix (`beam`), shared with the
  # production release build.
  languages.elixir.enable = true;

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

    # The app's own MCP endpoint (dev server). Login required: Claude Code
    # runs the OAuth 2.1 discovery/registration flow on the first 401.
    mcpServers.varsel = {
      type = "http";
      url = "http://localhost:4000/mcp";
    };

    # Tidewave (dev-only runtime introspection; plugged in the endpoint
    # under MIX_ENV=dev).
    mcpServers.tidewave = {
      type = "http";
      url = "http://localhost:4000/tidewave/mcp";
    };

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

    # git-hooks.nix has no built-in sobelow hook. Run it as a project-wide
    # security scan (fails on findings via `exit: :low` in .sobelow-conf).
    sobelow = {
      enable = true;
      name = "sobelow";
      entry = "mix sobelow";
      files = "\\.exs?$";
      pass_filenames = false;
    };
  };
}
