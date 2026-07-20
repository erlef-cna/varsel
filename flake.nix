# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

{
  description = "Varsel — EEF CNA CVE case management";

  nixConfig = {
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    extra-substituters = "https://devenv.cachix.org";
  };

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

      # The mix release is built outside Nix (`MIX_ENV=prod mix release` in the
      # dev shell; it bundles externally downloaded NIFs, which a pure build
      # would forbid). Point VARSEL_RELEASE at it and evaluate with --impure.
      releaseSrc =
        let path = builtins.getEnv "VARSEL_RELEASE";
        in
        if path == "" then
          throw ''
            Set VARSEL_RELEASE to the mix release directory
            (usually $PWD/_build/prod/rel/varsel) and run nix with --impure.
          ''
        else
          builtins.path {
            path = /. + path;
            name = "varsel-mix-release";
          };

      container = system:
        import ./nix/container.nix {
          pkgs = nixpkgs.legacyPackages.${system};
          nix2container = nix2container.packages.${system}.nix2container;
          cvelint = nixpkgs.legacyPackages.${system}.callPackage ./nix/cvelint.nix { };
          inherit releaseSrc;
        };
    in
    {
      devShells = eachSystem shellSystems (system: {
        default = devenv.lib.mkShell {
          inherit inputs;
          pkgs = nixpkgs.legacyPackages.${system};
          modules = [ ./devenv.nix ];
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
        });

      # `nix run --impure .#copy-to -- docker://<image>:<tag> [skopeo flags]`
      # pushes the image straight from the store — no tarball, no daemon.
      apps = eachSystem containerSystems (system: {
        copy-to = {
          type = "app";
          program = "${(container system).copyTo}/bin/copy-to";
          meta.description = "Push the container image to a registry (skopeo)";
        };
      });
    };
}
