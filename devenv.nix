
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

{ pkgs, lib, config, inputs, ... }:

{
  packages = with pkgs; [
    git
  ];

  languages.elixir.enable = true;

  services.postgres.enable = true;

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
