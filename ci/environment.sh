# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
# source this file with arguments when you need to override the default toolchain location
TOOLCHAIN_HOME="$1"
CI_DIR_FROM_BASH_SOURCE="$( cd "$(dirname ${BASH_SOURCE[0]})" && pwd )"
if [[ "$JENKINS_VERSION" != "" ]]; then
  TOOLCHAIN_HOME="$HOME"
elif [[ "$TOOLCHAIN_HOME" != "" ]]; then
  TOOLCHAIN_HOME="$("$CI_DIR_FROM_BASH_SOURCE"/bashify_workspace.sh "$TOOLCHAIN_HOME")"
  export CARGO_HOME="$TOOLCHAIN_HOME/toolchains/.cargo"
  export RUSTUP_HOME="$TOOLCHAIN_HOME/toolchains/.rustup"
  export PATH="$CARGO_HOME/bin:$PATH"
  export RUSTC_WRAPPER="$CARGO_HOME"/bin/sccache
  export SCCACHE_DIR="$TOOLCHAIN_HOME"/cache

  # TODO: Verify that removing the following two lines and doing a clean build of the cache with
  # the new caching tar feature active/enabled fixes the issue with file attributes not persisting.
  # See AZP_CACHING_TAR in azure-pipelines.yml.
  chmod +x "$CARGO_HOME"/bin/* || echo "Couldn't make .cargo/bin files executable"
  find "$RUSTUP_HOME" -type f -ipath "*\/bin/*" -print0 |xargs -0 -I{} chmod +x "{}" || echo "Couldn't make .rustup/**/bin/* files executable"

  # the following lines may be uncommented when debugging issues with the toolchain
  #echo "which rustc: $(which rustc)"
  #echo "which rustup: $(which rustup)"
  #rustup show
  #rustc --version
fi
