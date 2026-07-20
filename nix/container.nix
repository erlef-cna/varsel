# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# The minimal production OCI image: nothing but the mix release, busybox, and
# cvelint. Everything comes from the nixpkgs pinned in devenv.lock, so the
# image uses the SAME package versions as the dev shell.
#
# The mix release is built outside Nix (plain `mix release`, same elixir as
# the dev shell — it bundles externally downloaded NIFs); `releaseSrc` is that
# directory imported into the store. This file only packages it.
{ pkgs, nix2container, cvelint, releaseSrc }:

let
  release = pkgs.runCommandLocal "varsel-release"
    {
      # The bundled ERTS binaries (beam.smp, the crypto NIF, ...) rpath into
      # erlang's runtime libraries (glibc, openssl, ncurses, ...). Nix only
      # registers references it finds among a build's inputs, so bring
      # erlang's closure into scope for the reference scanner — the libraries
      # then land in the image via the release's own references.
      erlangRuntimeDeps = pkgs.beam29Packages.erlang;

      # ... while the full erlang package itself (compiler, wx, docs — the
      # whole toolchain) must never end up in the image closure.
      disallowedRequisites = [ pkgs.beam29Packages.erlang ];
    } ''
    cp -r --no-preserve=mode,ownership ${releaseSrc} $out
    chmod -R u+w "$out"

    # The only files referencing the full erlang package are OTP's legacy
    # embedded-system boot script and the *.src templates — mix releases
    # never use them (bin/varsel drives erlexec directly). Dropping them is
    # what keeps the erlang toolchain out of the image; disallowedRequisites
    # above enforces it.
    rm "$out"/erts-*/bin/start "$out"/erts-*/bin/*.src
  '';

in
nix2container.buildImage {
  name = "ghcr.io/erlef-cna/varsel";

  # The release, cvelint, and a shell (busybox provides /bin/sh + the
  # coreutils the release's scripts call). ERTS runtime libraries and the
  # bash the nix-built scripts' shebangs point at come in via the release's
  # scanned references.
  copyToRoot = [ release cvelint pkgs.busybox ];

  # Split the store closure across many layers so pulls cache: glibc, ERTS
  # and the dependency .beam files land in their own layers and are reused
  # across deploys — only the layer(s) with changed code get re-pulled.
  maxLayers = 100;

  config = {
    Cmd = [ "/bin/server" ];
    Env = [ "PATH=/bin" "LANG=C.UTF-8" ];
  };
}
