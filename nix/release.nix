# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# Builds the production mix release with the same toolchain the dev shell
# uses, via the project's own mix aliases (assets.setup downloads the
# tailwind/esbuild binaries, npm installs the js deps). The build needs
# network access for all of that plus hex packages and the heroicons git
# dependency, so it opts out of the Nix sandbox instead of maintaining
# fixed-output hashes — a deliberate trade-off: Nix-controlled toolchain,
# network-dependent content. Builders must therefore be configured with
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

  env = {
    MIX_ENV = "prod";
    LC_ALL = "C.UTF-8";
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
    # git does not read SSL_CERT_FILE (needed for the heroicons dependency).
    GIT_SSL_CAINFO = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  };

  dontConfigure = true;

  buildPhase = ''
    runHook preBuild

    export HOME="$TMPDIR"
    mix local.hex --force
    mix local.rebar --force
    mix deps.get --only prod
    mix assets.setup
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
}
