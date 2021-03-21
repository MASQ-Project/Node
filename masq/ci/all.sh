#!/bin/bash -xev
# Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
TOOLCHAIN_HOME="$1"

#export RUSTC_WRAPPER="$HOME/.cargo/bin/sccache"
pushd "$CI_DIR/.."
ci/lint.sh

if  [[ "$OSTYPE" == "msys" ]]; then
[[ $GITHUB_ACTIONS -eq true ]] && netsh advfirewall set allprofiles state off
fi

ci/unit_tests.sh

if  [[ "$OSTYPE" == "msys" ]]; then
[[ $GITHUB_ACTIONS -eq true ]] && netsh advfirewall set allprofiles state on
fi

ci/integration_tests.sh "$TOOLCHAIN_HOME"
popd
