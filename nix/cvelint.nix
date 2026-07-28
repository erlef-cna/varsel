# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

# cvelint (https://github.com/mprpic/cvelint), packaged from the upstream
# release binaries. Shared by the dev shell (devenv.nix) and the production
# container (nix/container.nix) so both always run the same version.
{ stdenvNoCC, fetchurl }:

let
  version = "0.7.0";

  assets = {
    "aarch64-darwin" = {
      asset = "cvelint_Darwin_arm64.tar.gz";
      sha256 = "c61914ea9ea5efe79077e5b71bd66b09eadac1cc598157710c87ee9c85eda869";
    };
    "x86_64-darwin" = {
      asset = "cvelint_Darwin_x86_64.tar.gz";
      sha256 = "275f56e340e4a3932ccddc97ef229730006daa89787bb5e8bfca5a0f49f18d12";
    };
    "aarch64-linux" = {
      asset = "cvelint_Linux_arm64.tar.gz";
      sha256 = "0e5a56e4673276d900aa229bf6f506103b924b70fccf0afeb3a0c51baf26f707";
    };
    "x86_64-linux" = {
      asset = "cvelint_Linux_x86_64.tar.gz";
      sha256 = "85e1aa63935584cce44a326cc07d42bcbdf3b3f9c7d899275c9fd08c5ca6ef9a";
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
