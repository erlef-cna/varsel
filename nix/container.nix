# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# The minimal production OCI image: nothing but the mix release
# (nix/release.nix), busybox, and cvelint. Everything comes from the same
# nixpkgs pin as the dev shell.
{ pkgs, nix2container, cvelint, release }:

nix2container.buildImage {
  name = "ghcr.io/erlef-cna/varsel";

  # The release, cvelint, a shell (busybox provides /bin/sh + the coreutils
  # the release's scripts call), and the CA root store for outbound TLS.
  # ERTS runtime libraries come in via the release's scanned references.
  # fakeNss supplies /etc/passwd + /etc/group; Fly's SSH daemon resolves
  # `root` via getpwnam and rejects sessions without them.
  copyToRoot = [ release cvelint pkgs.busybox pkgs.cacert pkgs.dockerTools.fakeNss ];

  # Split the store closure across many layers so pulls cache: glibc, ERTS
  # and the dependency .beam files land in their own layers and are reused
  # across deploys — only the layer(s) with changed code get re-pulled.
  maxLayers = 100;

  config = {
    Cmd = [ "/bin/server" ];
    Env = [
      "PATH=/bin"
      "LANG=C.UTF-8"
      # OTP's os_cacerts lookup honors this before probing distro paths.
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
    ];
  };
}
