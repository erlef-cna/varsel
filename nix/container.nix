# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# Builds the minimal production OCI image: nothing but the mix release, a
# shell, and cvelint. Everything comes from the caller's (devenv's) locked
# nixpkgs, so the image uses the SAME package versions as the dev shell — no
# separate pins to keep in sync.
#
# The mix release is built outside Nix (plain `mix release`, same elixir as the
# dev shell) and staged at ../container/release; this only imports and packages
# it.
{ pkgs, nix2container, cvelint }:

let
  # The staged mix release, imported into the store. Its boot scripts embed the
  # build-time /nix/store path of the full erlang package (an ERTS ROOTDIR
  # fallback plus the elixir/iex shebangs); left intact, Nix would drag the
  # entire erlang closure (compiler, dialyzer, wx, docs — gigabytes) into the
  # image even though the release bundles its own ERTS. Strip it: the
  # $0-relative ROOTDIR lookup that precedes the fallback already resolves to
  # the bundled ERTS, and the bash shebangs become /bin/sh.
  release = pkgs.runCommandLocal "varsel-release" { } ''
    cp -r --no-preserve=mode,ownership ${../container/release} $out
    chmod -R u+w "$out"

    grep -rlZ '/nix/store/[a-z0-9]\{32\}-erlang-\|#!/nix/store/[^/]*/bin/sh' "$out" \
      | while IFS= read -r -d "" f; do
      sed -i \
        -e 's,#!/nix/store/[^/]*/bin/sh,#!/bin/sh,g' \
        -e 's,/nix/store/[a-z0-9]\{32\}-erlang-[^/]*/lib/erlang,${placeholder "out"}/lib/erlang,g' \
        "$f"
    done

    if grep -rq '/nix/store/[a-z0-9]\{32\}-erlang-' "$out"; then
      echo "error: release still references the full erlang package:" >&2
      grep -rl '/nix/store/[a-z0-9]\{32\}-erlang-' "$out" >&2
      exit 1
    fi
  '';

in
nix2container.buildImage {
  name = "ghcr.io/erlef-cna/varsel";
  tag = "edge";

  # The release, cvelint, and a shell (busybox provides sh + the coreutils the
  # release's boot scripts call). ERTS runtime libs come via the release's own
  # references.
  copyToRoot = [ release cvelint pkgs.busybox ];

  config = {
    Cmd = [ "/bin/server" ];
    Env = [ "PATH=/bin" "LANG=C.UTF-8" ];
  };
}
