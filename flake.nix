# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

{
  description = "Varsel — EEF CNA CVE case management";

  inputs = {
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    devenv.url = "github:cachix/devenv";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix2container = {
      url = "github:nlewo/nix2container";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, devenv, nix2container, ... } @ inputs:
    let
      lib = nixpkgs.lib;

      shellSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      # The image ships a linux mix release, so it only exists for linux.
      containerSystems = [ "x86_64-linux" "aarch64-linux" ];

      eachSystem = systems: f:
        builtins.listToAttrs (map (system: {
          name = system;
          value = f system;
        }) systems);

      # THE erlang/elixir of this project — the dev shell and the release
      # both get their toolchain from here, so a version bump (or build-flag
      # override) is a single change.
      beam = system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          erlang = pkgs.beam29Packages.erlang;
          elixir = pkgs.beam29Packages.elixir_1_20;
        };

      # The mix release, built inside Nix from the flake source. The build
      # opts out of the sandbox for network access (see nix/release.nix), so
      # builders need `sandbox = relaxed`.
      release = system:
        nixpkgs.legacyPackages.${system}.callPackage ./nix/release.nix {
          src = self;
          inherit (beam system) erlang elixir;
        };

      container = system:
        import ./nix/container.nix {
          pkgs = nixpkgs.legacyPackages.${system};
          nix2container = nix2container.packages.${system}.nix2container;
          cvelint = nixpkgs.legacyPackages.${system}.callPackage ./nix/cvelint.nix { };
          release = release system;
        };
    in
    {
      devShells = eachSystem shellSystems (system: {
        default = devenv.lib.mkShell {
          inherit inputs;
          pkgs = nixpkgs.legacyPackages.${system};
          modules = [
            ./devenv.nix
            # Same toolchain as the release (see `beam` above).
            { languages.elixir.package = (beam system).elixir; }
          ];
        };
      });

      packages = eachSystem shellSystems (system:
        {
          # Entry points for `devenv up` / `devenv test` in flake mode.
          devenv-up = self.devShells.${system}.default.config.procfileScript;
          devenv-test = self.devShells.${system}.default.config.test;
        }
        // lib.optionalAttrs (lib.elem system containerSystems) {
          container = container system;
          release = release system;
        });

      # `nix run .#copy-to -- docker://<image>:<tag> [skopeo flags]` builds
      # release + image and pushes straight from the store — no tarball, no
      # daemon.
      apps = eachSystem containerSystems (system: {
        copy-to = {
          type = "app";
          program = "${(container system).copyTo}/bin/copy-to";
          meta.description = "Push the container image to a registry (skopeo)";
        };
      });
    };
}
