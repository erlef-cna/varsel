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
, removeReferencesTo
, patchelf
, systemdLibs
, ncurses
, zlib
, openssl
, bashNonInteractive
, src
}:

let
  erlang = beam29Packages.erlang;
  elixir = beam29Packages.elixir_1_20;

  # One CA bundle, three dialects: no env var covers all tools — openssl
  # consumers (erlang, hex, curl) read SSL_CERT_FILE, git only its own
  # variable, node ignores both without --use-openssl-ca.
  caBundle = "${cacert}/etc/ssl/certs/ca-bundle.crt";

  commonEnv = {
    MIX_ENV = "prod";
    LC_ALL = "C.UTF-8";
    SSL_CERT_FILE = caBundle;
    GIT_SSL_CAINFO = caBundle;
    NODE_EXTRA_CA_CERTS = caBundle;
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

      # tailwind.install/esbuild.install auto-compiled the app skeleton
      # (this source tree has no lib/). Shipping that manifest would make
      # the real app look up to date in the release build — store mtimes
      # are all epoch — and it would compile to an empty app. Keep only
      # the dependency artifacts.
      rm -rf _build/prod/lib/varsel _build/prod/phoenix-colocated

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

  nativeBuildInputs = [ elixir nodejs git removeReferencesTo patchelf ];

  # The explicit contract of what the shipped release may depend on: the
  # ERTS runtime libraries (rpaths in the bundled binaries), bash for the
  # nix-patched script shebangs, and itself. Anything else — the
  # erlang/elixir toolchain, the deps cache derivation, compilers pulled in
  # via debug info — fails the build loudly, so image contents only ever
  # change deliberately.
  allowedReferences = [
    "out"
    (lib.getLib stdenv.cc.libc)
    stdenv.cc.cc.lib
    (lib.getLib ncurses)
    (lib.getLib zlib)
    (lib.getLib openssl)
    (lib.getLib systemdLibs)
    bashNonInteractive
  ];

  env = commonEnv;

  dontConfigure = true;

  buildPhase = ''
    runHook preBuild

    export HOME="$TMPDIR"
    # Plain cp keeps the execute bits (the tailwind/esbuild binaries live in
    # _build); the store copies are read-only, so re-add write afterwards.
    cp -r ${deps}/.mix "$HOME/.mix"
    cp -r ${deps}/deps ${deps}/_build .
    cp -r ${deps}/assets/node_modules assets/
    chmod -R u+w "$HOME/.mix" deps _build assets/node_modules

    # assets.deploy expects a compiled app (esbuild bundles the colocated
    # hooks extracted during compilation) — compare the assets.build alias,
    # which starts with "compile".
    mix compile
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

    # NIFs compiled during the deps build (bcrypt, picosat) carry gcc and
    # glibc-dev paths in their debug info; stripping it drops those
    # references. The OTP-shipped .so files are already stripped but copied
    # read-only, so make them writable for the tools first.
    find "$out"/lib -name '*.so' -exec chmod u+w {} + -exec strip --strip-debug {} +

    # epmd genuinely links libsystemd, but its rpath names the full systemd
    # package — ~150 MiB of gnutls/curl/pam/... in the image. Point it at
    # the ABI-identical minimal systemd libs instead.
    chmod u+w "$out"/erts-*/bin/epmd
    patchelf --set-rpath "${lib.getLib systemdLibs}/lib:${lib.getLib stdenv.cc.libc}/lib" \
      "$out"/erts-*/bin/epmd

    # Inert toolchain paths in dependency artifacts: yecc-generated parsers
    # (gen_smtp, absinthe, hex_core) embed the location of erlang's
    # yeccpre.hrl in their line-info chunks, and the NIFs an rpath to the
    # deps derivation's never-existing lib/ (nix's ld-wrapper adds
    # -rpath $out/lib). Functionally dead, but enough for Nix to pull the
    # whole toolchain into the image — remove-references-to zeroes the
    # hashes in place (length-preserving, so .beam chunks stay valid).
    find "$out"/lib -type f \( -name '*.beam' -o -name '*.so' \) \
      -exec remove-references-to -t ${erlang} -t ${elixir} -t ${deps} {} +

    # allowedReferences enforces the closure contract, but fails without
    # naming files — check here first so the offenders end up in the build
    # log. Match the bare store hashes, mirroring Nix's reference scanner
    # (which triggers on the hash alone, full path or not).
    for pkg in ${erlang} ${elixir} ${deps}; do
      hash=$(basename "$pkg" | cut -c1-32)
      if grep -rl --binary-files=text "$hash" "$out"; then
        echo "error: release references $pkg (files above)" >&2
        exit 1
      fi
    done

    runHook postInstall
  '';

  # No generic fixup — the targeted strip/patchelf/scrub above is all the
  # post-processing this release gets.
  dontFixup = true;

  passthru = { inherit deps; };
}
