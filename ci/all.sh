#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
export ARGV_1="$1"

ci/format.sh

export RUST_BACKTRACE=1
#if github checkout fails, you can download csv database from db-ip.com and convert it locally by cargo run ip_country
if [[ $GITHUB_ACTIONS || "$ARGV_1" == "dbip" ]]; then
  git checkout origin/generated-source -- ip_country/src/dbip_country.rs
  ls -la ip_country/src/dbip_country.rs
fi
if [[ -z "${GITHUB_ACTIONS}" ]]; then
  bash ./install-hooks.sh
fi
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
ci/all.sh
echo "***                                             MASQ_LIB TAIL                                         ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                               NODE HEAD                                           ***"
cd "$CI_DIR/../node"
ci/all.sh
echo "***                                               NODE TAIL                                           ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                           DNS UTILITY HEAD                                        ***"
cd "$CI_DIR/../dns_utility"
ci/all.sh
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
ci/all.sh
echo "***                                             AUTOMAP TAIL                                          ***"
echo "*********************************************************************************************************"
echo "*********************************************************************************************************"
echo "***                                           IP COUNTRY HEAD                                         ***"
cd "$CI_DIR/../ip_country"
ci/all.sh
echo "***                                           IP COUNTRY TAIL                                         ***"
echo "*********************************************************************************************************"
