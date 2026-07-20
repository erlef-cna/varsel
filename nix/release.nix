# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# Builds the production mix release with the same toolchain the dev shell
# uses, via the project's own mix aliases. Split in two:
#
#  * `deps` fetches and compiles everything external (hex deps, npm deps,
#    the tailwind/esbuild binaries, hex/rebar themselves). Its source is
#    only the files that determine dependencies, so Nix reuses the result
#    until mix.exs/mix.lock/config/package(-lock).json change.
#  * the release itself compiles the app and assets on top of that.
#
# Both need network (hex, npm, binary downloads, the heroicons git dep), so
# they opt out of the Nix sandbox instead of maintaining fixed-output
# hashes — a deliberate trade-off: Nix-controlled toolchain,
# network-dependent content. Builders must be configured with
# `sandbox = relaxed` (CI sets this; on dev machines only the linux
# builder needs it).
{ lib
, stdenv
, beam29Packages
, nodejs
, git
, cacert
, src
}:

let
  erlang = beam29Packages.erlang;
  elixir = beam29Packages.elixir_1_20;

  commonEnv = {
    MIX_ENV = "prod";
    LC_ALL = "C.UTF-8";
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
    # git and node each have their own idea of where CA roots come from.
    GIT_SSL_CAINFO = "${cacert}/etc/ssl/certs/ca-bundle.crt";
    NODE_EXTRA_CA_CERTS = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  };

  # Only the files that determine what the dependencies are. Anything else
  # changing (app code, assets, ...) leaves the deps derivation untouched.
  depsSrc = lib.cleanSourceWith {
    name = "varsel-deps-src";
    inherit src;
    filter = path: _type:
      let rel = lib.removePrefix (toString src + "/") (toString path);
      in
      builtins.elem rel [
        "mix.exs"
        "mix.lock"
        "config"
        "assets"
        "assets/package.json"
        "assets/package-lock.json"
      ] || lib.hasPrefix "config/" rel;
  };

  deps = stdenv.mkDerivation {
    name = "varsel-deps";
    src = depsSrc;

    __noChroot = true;

    nativeBuildInputs = [ elixir nodejs git ];

    env = commonEnv;

    dontConfigure = true;
    dontFixup = true;

    buildPhase = ''
      runHook preBuild

      export HOME="$TMPDIR"
      mix local.hex --force
      mix local.rebar --force
      mix deps.get --only prod
      mix deps.compile
      mix assets.setup

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall

      mkdir -p "$out/assets"
      cp -r deps _build "$out/"
      cp -r assets/node_modules "$out/assets/"
      cp -r "$HOME/.mix" "$out/.mix"

      runHook postInstall
    '';
  };
in
stdenv.mkDerivation {
  name = "varsel-release";
  inherit src;

  __noChroot = true;

  nativeBuildInputs = [ elixir nodejs git ];

  # The release bundles its own ERTS, whose binaries rpath into erlang's
  # runtime libraries (glibc, openssl, ncurses, ...) — having erlang among
  # the inputs keeps those visible to Nix's reference scanner, so they land
  # in the container closure. The erlang/elixir packages themselves (the
  # whole toolchain) must never be referenced.
  disallowedRequisites = [ erlang elixir ];

  env = commonEnv;

  dontConfigure = true;

  buildPhase = ''
    runHook preBuild

    export HOME="$TMPDIR"
    cp -r --no-preserve=mode,ownership ${deps}/.mix "$HOME/.mix"
    cp -r --no-preserve=mode,ownership ${deps}/deps ${deps}/_build .
    cp -r --no-preserve=mode,ownership ${deps}/assets/node_modules assets/

    mix assets.deploy

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mix release --path "$out"

    # The only files in a release referencing the full erlang package are
    # OTP's legacy embedded-system boot script and the *.src templates —
    # mix releases never use them (bin/varsel drives erlexec directly).
    rm "$out"/erts-*/bin/start "$out"/erts-*/bin/*.src

    # disallowedRequisites enforces the toolchain stays out of the closure,
    # but fails without naming files — check here first so the offenders
    # end up in the build log.
    if grep -rl --binary-files=text -e ${erlang} -e ${elixir} "$out"; then
      echo "error: release references the erlang/elixir toolchain (files above)" >&2
      exit 1
    fi

    runHook postInstall
  '';

  # Ship the release exactly as mix assembled it — no stripping, no shebang
  # or rpath rewriting.
  dontFixup = true;

  passthru = { inherit deps; };
}
