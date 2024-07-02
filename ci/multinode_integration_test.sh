#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

if [[ "$JENKINS_VERSION" != "" ]]; then
  PARENT_DIR="$1"
else
  PARENT_DIR=""

fi


case "$OSTYPE" in
  msys)
    echo "Multinode Integration Tests don't run under Windows"
    ;;
  Darwin | darwin*)
    echo "Multinode Integration Tests don't run under macOS"
    ;;
  linux*)
    export RUSTFLAGS="-D warnings -Anon-snake-case"

    pushd "$CI_DIR/../multinode_integration_tests"
    ci/all.sh "$PARENT_DIR" || pwd
    popd
    ;;
  *)
    exit 1
    ;;
esac
