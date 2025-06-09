#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
PARENT_DIR="$1"

ci/format.sh

export RUST_BACKTRACE=1

# Remove these two lines to slow down the build
which sccache || cargo install --version 0.4.1 sccache || echo "Skipping sccache installation"  # Should do significant work only once
#export CARGO_TARGET_DIR="$CI_DIR/../cargo-cache"
export SCCACHE_DIR="$HOME/.cargo/sccache"
#export RUSTC_WRAPPER="$HOME/.cargo/bin/sccache"
SCCACHE_IDLE_TIMEOUT=0 sccache --start-server || echo "sccache server already running"
export RUSTFLAGS="-D warnings -Anon-snake-case"

echo "*********************************************************************************************************"
echo "***                                             MASQ_LIB HEAD                                         ***"
cd "$CI_DIR/../masq_lib"
ci/all.sh "$PARENT_DIR"
echo "***                                             MASQ_LIB TAIL                                         ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                               NODE HEAD                                           ***"
cd "$CI_DIR/../node"
ci/all.sh "$PARENT_DIR"
echo "***                                               NODE TAIL                                           ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                           DNS UTILITY HEAD                                        ***"
cd "$CI_DIR/../dns_utility"
ci/all.sh "$PARENT_DIR"
echo "***                                           DNS UTILITY TAIL                                        ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                             MASQ UI HEAD                                          ***"
cd "$CI_DIR/../masq"
ci/all.sh
echo "***                                             MASQ UI TAIL                                          ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                             AUTOMAP HEAD                                          ***"
cd "$CI_DIR/../automap"
ci/all.sh "$PARENT_DIR"
echo "***                                             AUTOMAP TAIL                                          ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                           IP COUNTRY HEAD                                         ***"
cd "$CI_DIR/../ip_country"
ci/all.sh "$PARENT_DIR"
echo "***                                           IP COUNTRY TAIL                                         ***"
echo "*********************************************************************************************************"

