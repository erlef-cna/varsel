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

  # A scratch image has no /tmp, and the release runs as a non-root user that
  # could not create one. Exile needs it for the socket it hands its spawner
  # (System.tmp_dir!/0), and the release launcher renders its runtime config
  # there. The mode is set via `perms` below: the store normalizes everything
  # it holds to read-only, so a chmod here would not survive.
  tmpDir = pkgs.runCommand "tmp-dir" { } "mkdir -p $out/tmp";
in
nix2container.buildImage {
  name = "ghcr.io/erlef-cna/varsel";

  # The release, cvelint, a shell (busybox provides /bin/sh + the coreutils
  # the release's scripts call), and the CA root store for outbound TLS.
  # ERTS runtime libraries come in via the release's scanned references.
  # fakeNss supplies /etc/passwd + /etc/group (and /var/empty): Fly's SSH
  # daemon resolves `root` via getpwnam and rejects sessions without them,
  # and the `nobody` entry backs the non-root User set below.
  copyToRoot = [ release cvelint pkgs.busybox pkgs.cacert otpCacerts pkgs.dockerTools.fakeNss tmpDir ];

  # Split the store closure across many layers so pulls cache: glibc, ERTS
  # and the dependency .beam files land in their own layers and are reused
  # across deploys — only the layer(s) with changed code get re-pulled.
  maxLayers = 100;

  # 1777 (sticky, world-writable) is the standard /tmp mode, and keeps the
  # directory usable whatever uid the container runs as.
  perms = [
    {
      path = tmpDir;
      regex = "/tmp";
      mode = "1777";
    }
  ];

  config = {
    Cmd = [ "/bin/server" ];

    # Nothing needs root: the endpoint binds 4000, and TLS terminates at the
    # edge. `nobody` and its group come from fakeNss above.
    User = "65534:65534";

    Env = [
      "PATH=/bin"
      "LANG=C.UTF-8"
      # The launcher defaults RELEASE_TMP to $RELEASE_ROOT/tmp — inside the
      # read-only store path — and writes a rendered runtime config there on
      # every boot. Point it at the one writable directory instead, so the
      # rest of the filesystem can be mounted read-only.
      "RELEASE_TMP=/tmp"
      # HOME is unset otherwise, which erlexec and Mix both fall back on.
      "HOME=/var/empty"
    ];
  };
}
