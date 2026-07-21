# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# The minimal production OCI image: nothing but the mix release
# (nix/release.nix), busybox, and cvelint. Everything comes from the same
# nixpkgs pin as the dev shell.
{ pkgs, nix2container, cvelint, release }:

let
  # OTP's :pubkey_os_cacerts probes a fixed list of distro paths (and ignores
  # SSL_CERT_FILE); nixpkgs' /etc/ssl/certs/ca-bundle.crt is not on it, so
  # expose the bundle under the Debian name OTP checks first. The symlink must
  # be relative: copyToRoot copies package contents into the image root
  # without shipping the packages' own store paths, so a store-path target
  # would dangle. It resolves against cacert's bundle merged into the same
  # directory.
  otpCacerts = pkgs.runCommand "otp-cacerts" { } ''
    mkdir -p $out/etc/ssl/certs
    ln -s ca-bundle.crt $out/etc/ssl/certs/ca-certificates.crt
  '';
in
nix2container.buildImage {
  name = "ghcr.io/erlef-cna/varsel";

  # The release, cvelint, a shell (busybox provides /bin/sh + the coreutils
  # the release's scripts call), and the CA root store for outbound TLS.
  # ERTS runtime libraries come in via the release's scanned references.
  # fakeNss supplies /etc/passwd + /etc/group; Fly's SSH daemon resolves
  # `root` via getpwnam and rejects sessions without them.
  copyToRoot = [ release cvelint pkgs.busybox pkgs.cacert otpCacerts pkgs.dockerTools.fakeNss ];

  # Split the store closure across many layers so pulls cache: glibc, ERTS
  # and the dependency .beam files land in their own layers and are reused
  # across deploys — only the layer(s) with changed code get re-pulled.
  maxLayers = 100;

  config = {
    Cmd = [ "/bin/server" ];
    Env = [
      "PATH=/bin"
      "LANG=C.UTF-8"
    ];
  };
}
