# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# Builds the production mix release with the same toolchain the dev shell
# uses, as a pipeline of derivations each keyed on exactly the files that
# affect it — Nix reuses every stage whose inputs didn't change:
#
#   assets/package(-lock).json  →  nodeModules   (npm ci)
#   mix.exs + mix.lock          →  depsFetch     (mix deps.get)
#   ... + config/               →  depsCompiled  (mix deps.compile
#                                                 + bundler binaries)
#   everything                  →  the release   (compile, assets, release)
#
# The network-touching stages opt out of the Nix sandbox (__noChroot)
# instead of maintaining fixed-output hashes — a deliberate trade-off:
# Nix-controlled toolchain, network-dependent content. Builders must be
# configured with `sandbox = relaxed` (CI sets this; on dev machines only
# the linux builder needs it).
{ lib
, stdenv
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
  # Passed explicitly from flake.nix (`beam`) — shared with the dev shell.
, erlang
, elixir
}:

let
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

  # A source containing only the given repo-relative files/directories, so
  # unrelated changes don't invalidate the stage built from it.
  srcSubset = name: paths:
    lib.cleanSourceWith {
      inherit name src;
      filter = path: type:
        let rel = lib.removePrefix (toString src + "/") (toString path);
        in
        lib.any
          (p:
            rel == p
            # inside a listed directory
            || lib.hasPrefix "${p}/" rel
            # ancestor directory of a listed path (needed for traversal)
            || (type == "directory" && lib.hasPrefix "${rel}/" p))
          paths;
    };

  # npm dependencies, keyed on the npm manifests alone.
  nodeModules = stdenv.mkDerivation {
    name = "varsel-node-modules";
    src = srcSubset "varsel-npm-src" [ "assets/package.json" "assets/package-lock.json" ];

    __noChroot = true;
    nativeBuildInputs = [ nodejs ];
    env = commonEnv;
    dontConfigure = true;
    dontFixup = true;

    buildPhase = ''
      runHook preBuild
      export HOME="$TMPDIR"
      npm ci --prefix assets
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mv assets/node_modules "$out"
      runHook postInstall
    '';
  };

  # Fetched (not compiled) mix dependencies plus hex/rebar themselves,
  # keyed on mix.exs + mix.lock alone.
  depsFetch = stdenv.mkDerivation {
    name = "varsel-deps";
    src = srcSubset "varsel-deps-src" [ "mix.exs" "mix.lock" ];

    __noChroot = true;
    nativeBuildInputs = [ elixir git ];
    env = commonEnv;
    dontConfigure = true;
    dontFixup = true;

    buildPhase = ''
      runHook preBuild
      export HOME="$TMPDIR"
      mix local.hex --force
      mix local.rebar --force
      mix deps.get --only prod
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      cp -r deps "$out/"
      cp -r "$HOME/.mix" "$out/.mix"
      runHook postInstall
    '';
  };

  # Compiled dependencies and the tailwind/esbuild binaries (their version
  # pins live in config/), keyed on mix.exs + mix.lock + config/. Outputs
  # deps/ too: port compilers (bcrypt, picosat) write their artifacts into
  # the dep source trees, which _build links to relatively.
  depsCompiled = stdenv.mkDerivation {
    name = "varsel-deps-compiled";
    src = srcSubset "varsel-deps-compile-src" [ "mix.exs" "mix.lock" "config" ];

    __noChroot = true;
    nativeBuildInputs = [ elixir git ];
    env = commonEnv;
    dontConfigure = true;
    dontFixup = true;

    buildPhase = ''
      runHook preBuild

      export HOME="$TMPDIR"
      cp -r ${depsFetch}/.mix "$HOME/.mix"
      cp -r ${depsFetch}/deps .
      chmod -R u+w "$HOME/.mix" deps

      mix deps.compile
      mix tailwind.install --if-missing
      mix esbuild.install --if-missing

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

      mkdir -p "$out"
      cp -r deps _build "$out/"

      runHook postInstall
    '';
  };

  # CycloneDX SBOMs for the application dependencies: hex deps via the
  # mix_sbom escript (installed here, NOT a project dep — it would list
  # itself in the BOM), npm deps via `npm sbom`. The nix-level SBOM of the
  # image closure is generated in the release workflow (sbomnix needs the
  # store database, which is out of reach inside a build) and merged with
  # these there.
  depsSbom = stdenv.mkDerivation {
    name = "varsel-deps-sbom";
    src = srcSubset "varsel-sbom-src" [
      "mix.exs"
      "mix.lock"
      "config"
      "assets/package.json"
      "assets/package-lock.json"
    ];

    # Network for escript.install; the SBOM generation itself is offline.
    __noChroot = true;
    # erlang for the escript shebang (`/usr/bin/env escript`).
    nativeBuildInputs = [ elixir erlang nodejs git ];
    env = commonEnv;
    dontConfigure = true;
    dontFixup = true;

    buildPhase = ''
      runHook preBuild

      export HOME="$TMPDIR"
      cp -r ${depsFetch}/.mix "$HOME/.mix"
      cp -r ${depsFetch}/deps .
      chmod -R u+w "$HOME/.mix" deps

      mix escript.install hex sbom 0.10.0 --force
      "$HOME/.mix/escripts/mix_sbom" cyclonedx \
        --output=mix.cdx.json --format=json --only prod .

      cp -r ${nodeModules} assets/node_modules
      (cd assets && npm sbom --sbom-format cyclonedx --omit dev) > npm.cdx.json

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      install -D -t "$out" mix.cdx.json npm.cdx.json
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
  # erlang/elixir toolchain, the intermediate stage derivations, compilers
  # pulled in via debug info — fails the build loudly, so image contents
  # only ever change deliberately.
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
    cp -r ${depsFetch}/.mix "$HOME/.mix"
    cp -r ${depsCompiled}/deps ${depsCompiled}/_build .
    cp -r ${nodeModules} assets/node_modules
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
    # deps stage's never-existing lib/ (nix's ld-wrapper adds
    # -rpath $out/lib). Functionally dead, but enough for Nix to pull the
    # whole toolchain into the image — remove-references-to zeroes the
    # hashes in place (length-preserving, so .beam chunks stay valid).
    find "$out"/lib -type f \( -name '*.beam' -o -name '*.so' \) \
      -exec remove-references-to -t ${erlang} -t ${elixir} -t ${depsCompiled} {} +

    # allowedReferences enforces the closure contract, but fails without
    # naming files — check here first so the offenders end up in the build
    # log. Match the bare store hashes, mirroring Nix's reference scanner
    # (which triggers on the hash alone, full path or not).
    for pkg in ${erlang} ${elixir} ${nodeModules} ${depsFetch} ${depsCompiled}; do
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

  passthru = { inherit nodeModules depsFetch depsCompiled depsSbom; };
}
