# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# cvelint (https://github.com/mprpic/cvelint), packaged from the upstream
# release binaries. Shared by the dev shell (devenv.nix) and the production
# container (nix/container.nix) so both always run the same version.
{ stdenvNoCC, fetchurl }:

let
  version = "0.6.0";

  assets = {
    "aarch64-darwin" = {
      asset = "cvelint_Darwin_arm64.tar.gz";
      sha256 = "f5b1ad176543424197de890397d4fb139b56f23b3ca0be0b44cbcaedad579efc";
    };
    "x86_64-darwin" = {
      asset = "cvelint_Darwin_x86_64.tar.gz";
      sha256 = "7fe439fcf4d05f643276edcfc207fc5bded7a587cd4a7765268de4e30a4128e2";
    };
    "aarch64-linux" = {
      asset = "cvelint_Linux_arm64.tar.gz";
      sha256 = "c69d173d04343f8392a1eb8c9b41e4af622bbc83caf08d78de01cd2149ddae48";
    };
    "x86_64-linux" = {
      asset = "cvelint_Linux_x86_64.tar.gz";
      sha256 = "88078c84238ae13053328fc28c4ab9c63482d3b4d4ac3b1366a168be7d3e65cf";
    };
  };

  asset =
    assets.${stdenvNoCC.hostPlatform.system}
      or (throw "cvelint: unsupported system ${stdenvNoCC.hostPlatform.system}");
in
stdenvNoCC.mkDerivation {
  pname = "cvelint";
  inherit version;

  src = fetchurl {
    url = "https://github.com/mprpic/cvelint/releases/download/v${version}/${asset.asset}";
    inherit (asset) sha256;
  };

  sourceRoot = ".";

  installPhase = ''
    install -Dm755 cvelint $out/bin/cvelint
  '';
}
