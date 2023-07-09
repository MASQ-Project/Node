#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
PARENT_DIR="$1"

export RUST_BACKTRACE=1

# Remove these two lines to slow down the build
which sccache || cargo install sccache || echo "Skipping sccache installation"  # Should do significant work only once
#export CARGO_TARGET_DIR="$CI_DIR/../cargo-cache"
export SCCACHE_DIR="$HOME/.cargo/sccache"
#export RUSTC_WRAPPER="$HOME/.cargo/bin/sccache"
SCCACHE_IDLE_TIMEOUT=0 sccache --start-server || echo "sccache server already running"
export RUSTFLAGS="-D warnings -Anon-snake-case"

echo "*********************************************************************************************************"
echo "***                                               NODE HEAD                                           ***"
cd "$CI_DIR/../node"
ci/integration_tests.sh "$PARENT_DIR"
echo "***                                               NODE TAIL                                           ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                           DNS UTILITY HEAD                                        ***"
cd "$CI_DIR/../dns_utility"
ci/integration_tests.sh "$PARENT_DIR"
echo "***                                           DNS UTILITY TAIL                                        ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                             MASQ UI HEAD                                          ***"
cd "$CI_DIR/../masq"
ci/integration_tests.sh
echo "***                                             MASQ UI TAIL                                          ***"
echo "*********************************************************************************************************"
